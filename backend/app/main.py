import os
import uuid
from typing import List, Optional
from fastapi import FastAPI, BackgroundTasks, Depends, HTTPException, status, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, or_

# 專案內部模組
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
    version="1.1.0",
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

# 資料庫 Session 依賴
async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

# ==================== Pydantic Schemas ====================

class CreateScanRequest(BaseModel):
    target: str
    tools: Optional[List[str]] = None

class CreateUserRequest(BaseModel):
    username: str
    password: str
    role: UserRole = UserRole.ANALYST

class UpdateUserRequest(BaseModel):
    password: Optional[str] = None
    role: Optional[UserRole] = None
    is_active: Optional[bool] = None

# ==================== 系統初始化 ====================

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

# ==================== 認證與身分 API ====================

@app.post("/api/auth/login", summary="登入取得 JWT Token")
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
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="該帳號已被停用")

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

# ==================== 使用者帳號管理 (限 ADMIN) ====================

@app.get("/api/users", summary="取得所有使用者清單")
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN]))
):
    result = await db.execute(select(User).order_by(desc(User.created_at)))
    users = result.scalars().all()
    return [
        {
            "id": str(u.id),
            "username": u.username,
            "role": u.role,
            "is_active": u.is_active,
            "created_at": u.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }
        for u in users
    ]

@app.post("/api/users", summary="建立新使用者帳號")
async def create_user(
    payload: CreateUserRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN]))
):
    result = await db.execute(select(User).where(User.username == payload.username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="該使用者名稱已存在")

    new_user = User(
        username=payload.username,
        hashed_password=get_password_hash(payload.password),
        role=payload.role,
        is_active=True
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return {"message": "使用者建立成功", "id": str(new_user.id)}

@app.put("/api/users/{user_id}", summary="修改使用者密碼或權限角色")
async def update_user(
    user_id: uuid.UUID,
    payload: UpdateUserRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN]))
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="找不到該使用者")

    if payload.password:
        user.hashed_password = get_password_hash(payload.password)
    if payload.role:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active

    await db.commit()
    return {"message": "使用者資料更新成功"}

@app.delete("/api/users/{user_id}", summary="刪除使用者帳號")
async def delete_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN]))
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="找不到該使用者")
    if user.username == "admin":
        raise HTTPException(status_code=400, detail="不可刪除預設管理員帳號")

    await db.delete(user)
    await db.commit()
    return {"message": "使用者已成功刪除"}

# ==================== 非同步調查流水線 ====================

async def execute_investigation_pipeline(case_id: uuid.UUID, target: str, target_type: str, selected_tools: Optional[List[str]]):
    async with AsyncSessionLocal() as db:
        case = await db.get(Case, case_id)
        if not case:
            return
        
        case.status = CaseStatus.RUNNING
        await db.commit()

        discovered_entities_text = []
        is_tool_enabled = lambda name: selected_tools is None or name in selected_tools

        try:
            # 1. 原生高速探測引擎 (保底資料)
            if is_tool_enabled("native_engine"):
                native_res = await OSINTModules.run_native_recon(target, target_type)
                for r in native_res.get("results", []):
                    ent = Entity(case_id=case.id, category="RECON_ASSET", value=r, source_tool="native_engine")
                    db.add(ent)
                    discovered_entities_text.append(r)

            # 2. 人名探測模組
            if target_type == "PERSON":
                expanded = InputNormalizer.expand_person_identity(target)
                alias = expanded.get("pinyin_continuous") or target
                
                if is_tool_enabled("maigret"):
                    m_res = await OSINTModules.run_maigret(alias)
                    db.add(ScanLog(case_id=case.id, tool_name="maigret", status="COMPLETED", stdout_log=m_res["raw_log"], execution_time_sec=m_res["duration"]))
                    for a in m_res.get("accounts", []):
                        db.add(Entity(case_id=case.id, category="SOCIAL_PROFILE", value=a, source_tool="maigret"))
                        discovered_entities_text.append(f"Maigret 社群: {a}")

                if is_tool_enabled("sherlock"):
                    s_res = await OSINTModules.run_sherlock(alias)
                    db.add(ScanLog(case_id=case.id, tool_name="sherlock", status="COMPLETED", stdout_log=s_res["raw_log"], execution_time_sec=s_res["duration"]))
                    for a in s_res.get("accounts", []):
                        db.add(Entity(case_id=case.id, category="SOCIAL_PROFILE", value=a, source_tool="sherlock"))
                        discovered_entities_text.append(f"Sherlock 社群: {a}")

            # 3. 電子郵件模組
            elif target_type == "EMAIL":
                if is_tool_enabled("holehe"):
                    h_res = await OSINTModules.run_holehe(target)
                    db.add(ScanLog(case_id=case.id, tool_name="holehe", status="COMPLETED", stdout_log=h_res["raw_log"], execution_time_sec=h_res["duration"]))
                    for p in h_res.get("platforms", []):
                        db.add(Entity(case_id=case.id, category="SERVICE_REGISTRATION", value=p, source_tool="holehe"))
                        discovered_entities_text.append(f"已註冊平台: {p}")

            # 4. 電話號碼模組
            elif target_type == "PHONE":
                if is_tool_enabled("phoneinfoga"):
                    p_res = await OSINTModules.run_phoneinfoga(target)
                    db.add(ScanLog(case_id=case.id, tool_name="phoneinfoga", status="COMPLETED", stdout_log=p_res["raw_log"], execution_time_sec=p_res["duration"]))
                    for d in p_res.get("details", []):
                        db.add(Entity(case_id=case.id, category="PHONE_INTEL", value=d, source_tool="phoneinfoga"))
                        discovered_entities_text.append(f"門號情資: {d}")

            # 5. 網域與資產模組
            elif target_type == "DOMAIN":
                if is_tool_enabled("theHarvester"):
                    th_res = await OSINTModules.run_theharvester(target)
                    db.add(ScanLog(case_id=case.id, tool_name="theHarvester", status="COMPLETED", stdout_log=th_res["raw_log"], execution_time_sec=th_res["duration"]))

                if is_tool_enabled("amass"):
                    am_res = await OSINTModules.run_amass(target)
                    db.add(ScanLog(case_id=case.id, tool_name="amass", status="COMPLETED", stdout_log=am_res["raw_log"], execution_time_sec=am_res["duration"]))
                    for sub in am_res.get("subdomains", []):
                        db.add(Entity(case_id=case.id, category="SUBDOMAIN", value=sub, source_tool="amass"))
                        discovered_entities_text.append(f"Amass 子網域: {sub}")

                if is_tool_enabled("dnsrecon"):
                    dns_res = await OSINTModules.run_dnsrecon(target)
                    db.add(ScanLog(case_id=case.id, tool_name="dnsrecon", status="COMPLETED", stdout_log=dns_res["raw_log"], execution_time_sec=dns_res["duration"]))
                    for rec in dns_res.get("records", []):
                        db.add(Entity(case_id=case.id, category="DNS_RECORD", value=rec, source_tool="dnsrecon"))
                        discovered_entities_text.append(rec)

            # 6. AI 情報自動總結
            summary = await AIAnalyst.generate_dossier_summary(target, target_type, discovered_entities_text)
            case.ai_summary = summary
            case.status = CaseStatus.COMPLETED

        except Exception as e:
            case.status = CaseStatus.FAILED
            case.notes = f"流水線異常: {str(e)}"

        await db.commit()

# ==================== 調查管理 API ====================

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

    # 非同步背景執行探測流水線
    background_tasks.add_task(
        execute_investigation_pipeline,
        new_case.id,
        payload.target,
        detected_type,
        payload.tools
    )

    return {
        "case_id": str(new_case.id),
        "target": payload.target,
        "detected_type": detected_type,
        "status": "QUEUED"
    }

@app.get("/api/cases", summary="取得/搜尋調查案件列表")
async def list_cases(
    q: Optional[str] = Query(None, description="搜尋目標或標題關鍵字"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    stmt = select(Case).order_by(desc(Case.created_at))
    if q:
        stmt = stmt.where(or_(Case.target_input.ilike(f"%{q}%"), Case.title.ilike(f"%{q}%")))
    
    result = await db.execute(stmt.limit(100))
    cases = result.scalars().all()
    return [
        {
            "id": str(c.id),
            "title": c.title,
            "target": c.target_input,
            "type": c.target_type,
            "status": c.status,
            "created_at": c.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }
        for c in cases
    ]

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
        "created_at": case.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        "entities": [
            {
                "id": str(e.id),
                "category": e.category,
                "value": e.value,
                "tool": e.source_tool,
                "created_at": e.created_at.strftime("%Y-%m-%d %H:%M:%S")
            }
            for e in entities
        ],
        "logs": [
            {
                "tool": l.tool_name,
                "status": l.status,
                "duration": l.execution_time_sec,
                "created_at": l.created_at.strftime("%Y-%m-%d %H:%M:%S")
            }
            for l in logs
        ]
    }

@app.delete("/api/cases/{case_id}", summary="刪除特定案件 (限 ADMIN)")
async def delete_case(
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN]))
):
    case = await db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="找不到該案件")
    await db.delete(case)
    await db.commit()
    return {"message": "案件已成功刪除"}

# ==================== 前端靜態頁面掛載 ====================

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
