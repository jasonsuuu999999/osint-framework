import os
import uuid
from typing import List, Optional
from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

# 引入專案自訂模組
from app.models.database import (
    AsyncSessionLocal,
    init_db,
    Case,
    Entity,
    ScanLog,
    TargetType,
    CaseStatus,
    User,
    UserRole
)
from app.core.security import (
    get_password_hash,
    verify_password,
    create_access_token,
    get_current_user,
    require_roles
)
from app.nlp.normalizer import InputNormalizer
from app.modules.cli_runner import OSINTModules
from app.nlp.ai_analyst import AIAnalyst

app = FastAPI(
    title="OSINT Investigation Platform API",
    version="1.0.0",
    description="多語系多源 OSINT 自動化情報調查與視覺化平台"
)

# CORS 跨來源設定
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 資料庫 Session 依賴注入
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

# Pydantic 請求資料模型
class CreateScanRequest(BaseModel):
    target: str
    tools: Optional[List[str]] = None  # None 代表全自動一鍵執行

# 系統啟動事件：初始化 DB 表結構與預設管理員帳號
@app.on_event("startup")
async def on_startup():
    await init_db()
    async with AsyncSessionLocal() as session:
        result = await session.execute(select(User).where(User.username == "admin"))
        if not result.scalar_one_or_none():
            admin_user = User(
                username="admin",
                hashed_password=get_password_hash("admin123"),
                role=UserRole.ADMIN,
                is_active=True
            )
            session.add(admin_user)
            await session.commit()
            print("[*] 預設管理員帳號已建立：admin / admin123")

# ==================== 認證授權 API 路由 ====================

@app.post("/api/auth/login", summary="使用者登入取得 JWT Token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == form_data.username))
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="帳號或密碼錯誤",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="該帳號已被停用"
        )

    access_token = create_access_token(data={"sub": user.username, "role": user.role.value})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.username,
        "role": user.role.value
    }

@app.get("/api/auth/me", summary="取得當前登入者資訊")
async def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": str(current_user.id),
        "username": current_user.username,
        "role": current_user.role,
        "created_at": current_user.created_at
    }

# ==================== 調查任務背景流水線 ====================

async def execute_investigation_pipeline(case_id: uuid.UUID, target: str, target_type: str, selected_tools: Optional[List[str]]):
    async with AsyncSessionLocal() as db:
        case = await db.get(Case, case_id)
        if not case:
            return
        
        case.status = CaseStatus.RUNNING
        await db.commit()

        discovered_entities_text = []
        tools_to_run = selected_tools if selected_tools else ["maigret", "holehe", "theHarvester"]

        try:
            # 1. 人名 / 暱稱探測
            if target_type == "PERSON" and "maigret" in tools_to_run:
                expanded = InputNormalizer.expand_person_identity(target)
                alias_to_test = expanded.get("pinyin_continuous") or target
                
                res = await OSINTModules.run_maigret(alias_to_test)
                log = ScanLog(
                    case_id=case.id,
                    tool_name="maigret",
                    status="COMPLETED" if res["return_code"] == 0 else "WARNING",
                    stdout_log=res["raw_log"],
                    execution_time_sec=res["duration"]
                )
                db.add(log)

                for acc in res.get("accounts_found", []):
                    ent = Entity(case_id=case.id, category="SOCIAL_PROFILE", value=acc, source_tool="maigret")
                    db.add(ent)
                    discovered_entities_text.append(f"社群足跡: {acc}")

            # 2. Email 註冊反查
            elif target_type == "EMAIL" and "holehe" in tools_to_run:
                res = await OSINTModules.run_holehe(target)
                log = ScanLog(
                    case_id=case.id,
                    tool_name="holehe",
                    status="COMPLETED" if res["return_code"] == 0 else "WARNING",
                    stdout_log=res["raw_log"],
                    execution_time_sec=res["duration"]
                )
                db.add(log)

                for plat in res.get("platforms_found", []):
                    ent = Entity(case_id=case.id, category="SERVICE_REGISTRATION", value=plat, source_tool="holehe")
                    db.add(ent)
                    discovered_entities_text.append(f"註冊服務/記錄: {plat}")

            # 3. 網域資產枚舉
            elif target_type == "DOMAIN" and "theHarvester" in tools_to_run:
                res = await OSINTModules.run_theharvester(target)
                log = ScanLog(
                    case_id=case.id,
                    tool_name="theHarvester",
                    status="COMPLETED" if res["return_code"] == 0 else "WARNING",
                    stdout_log=res["raw_log"],
                    execution_time_sec=res["duration"]
                )
                db.add(log)

                for asset in res.get("assets_found", []):
                    ent = Entity(case_id=case.id, category="DOMAIN_ASSET", value=asset, source_tool="theHarvester")
                    db.add(ent)
                    discovered_entities_text.append(f"資產/記錄: {asset}")

            # 4. AI 情資自動彙整
            summary = await AIAnalyst.generate_dossier_summary(target, target_type, discovered_entities_text)
            case.ai_summary = summary
            case.status = CaseStatus.COMPLETED

        except Exception as e:
            case.status = CaseStatus.FAILED
            case.notes = f"Pipeline 執行異常: {str(e)}"

        await db.commit()

# ==================== 調查管理 API 路由 ====================

@app.post("/api/investigate", summary="建立並啟動情報調查任務")
async def create_investigation(
    payload: CreateScanRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN, UserRole.ANALYST]))
):
    detected_type = InputNormalizer.identify_type(payload.target)
    
    new_case = Case(
        title=f"Investigation: {payload.target}",
        target_input=payload.target,
        target_type=TargetType(detected_type) if detected_type in TargetType.__members__ else TargetType.UNKNOWN,
        status=CaseStatus.PENDING
    )
    db.add(new_case)
    await db.commit()
    await db.refresh(new_case)

    # 非同步背景執行探測
    background_tasks.add_task(
        execute_investigation_pipeline,
        new_case.id,
        payload.target,
        detected_type,
        payload.tools
    )

    return {
        "case_id": new_case.id,
        "target": payload.target,
        "detected_type": detected_type,
        "status": "QUEUED"
    }

@app.get("/api/cases/{case_id}", summary="取得調查案件詳情與實體節點")
async def get_case_detail(
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="找不到指定的調查案件")

    entities_res = await db.execute(select(Entity).where(Entity.case_id == case_id))
    entities = entities_res.scalars().all()

    logs_res = await db.execute(select(ScanLog).where(ScanLog.case_id == case_id))
    logs = logs_res.scalars().all()

    return {
        "id": str(case.id),
        "title": case.title,
        "target": case.target_input,
        "type": case.target_type,
        "status": case.status,
        "ai_summary": case.ai_summary,
        "notes": case.notes,
        "created_at": case.created_at,
        "entities": [
            {
                "id": str(e.id),
                "category": e.category,
                "value": e.value,
                "tool": e.source_tool,
                "created_at": e.created_at
            }
            for e in entities
        ],
        "logs": [
            {
                "tool": l.tool_name,
                "status": l.status,
                "duration": l.execution_time_sec,
                "created_at": l.created_at
            }
            for l in logs
        ]
    }

# ==================== 前端靜態檔案掛載 ====================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
frontend_dir = os.path.join(BASE_DIR, "frontend")

if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/", include_in_schema=False)
    async def read_index():
        index_file = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"message": "frontend/index.html 尚未建立"}
