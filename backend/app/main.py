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

# Project modules
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
    version="1.3.0",
    description="OSINT Automated Intelligence Gathering and Visualization Platform"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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

# ==================== System initialization ====================

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
            print("[*] The default account has been created.：admin / admin123")

# ==================== Authentication and Identity API ====================

@app.post("/api/auth/login", summary="Log in to get JWT Token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.username == form_data.username))
    user = result.scalar_one_or_none()
    
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Username/Password Error.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This account has been deactivated.")

    access_token = create_access_token(data={"sub": user.username, "role": user.role.value})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user.username,
        "role": user.role.value
    }

@app.get("/api/auth/me", summary="Get information of the currently logged-in user")
async def get_me(current_user: User = Depends(get_current_user)):
    return {
        "id": str(current_user.id),
        "username": current_user.username,
        "role": current_user.role,
        "created_at": current_user.created_at
    }

# ==================== User account management (ADMIN only) ====================

@app.get("/api/users", summary="Get a list of all users")
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

@app.post("/api/users", summary="Create a new user account")
async def create_user(
    payload: CreateUserRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN]))
):
    result = await db.execute(select(User).where(User.username == payload.username))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="The username already exists.")

    new_user = User(
        username=payload.username,
        hashed_password=get_password_hash(payload.password),
        role=payload.role,
        is_active=True
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)
    return {"message": "User creation successful", "id": str(new_user.id)}

@app.put("/api/users/{user_id}", summary="Change user password or permission roles")
async def update_user(
    user_id: uuid.UUID,
    payload: UpdateUserRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN]))
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="The user cannot be found.")

    if payload.password:
        user.hashed_password = get_password_hash(payload.password)
    if payload.role:
        user.role = payload.role
    if payload.is_active is not None:
        user.is_active = payload.is_active

    await db.commit()
    return {"message": "User data updated successfully"}

@app.delete("/api/users/{user_id}", summary="Delete user account")
async def delete_user(
    user_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN]))
):
    user = await db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="The user cannot be found.")
    if user.username == "admin":
        raise HTTPException(status_code=400, detail="Admin account cannot be deleted")

    await db.delete(user)
    await db.commit()
    return {"message": "The user has been successfully deleted."}

# ==================== asynchronous survey ====================

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
            # 1. Native detection engine
            if is_tool_enabled("native_engine"):
                native_res = await OSINTModules.run_native_recon(target, target_type)
                for r in native_res.get("results", []):
                    ent = Entity(case_id=case.id, category="RECON_ASSET", value=r, source_tool="native_engine")
                    db.add(ent)
                    discovered_entities_text.append(r)

            # 2. Name detection module
            if target_type == "PERSON":
                expanded = InputNormalizer.expand_person_identity(target)
                alias = expanded.get("pinyin_continuous") or target
                
                if is_tool_enabled("maigret"):
                    m_res = await OSINTModules.run_maigret(alias)
                    db.add(ScanLog(case_id=case.id, tool_name="maigret", status="COMPLETED", stdout_log=m_res["raw_log"], execution_time_sec=m_res["duration"]))
                    for a in m_res.get("accounts", []):
                        db.add(Entity(case_id=case.id, category="SOCIAL_PROFILE", value=a, source_tool="maigret"))
                        discovered_entities_text.append(f"Maigret: {a}")

                if is_tool_enabled("sherlock"):
                    s_res = await OSINTModules.run_sherlock(alias)
                    db.add(ScanLog(case_id=case.id, tool_name="sherlock", status="COMPLETED", stdout_log=s_res["raw_log"], execution_time_sec=s_res["duration"]))
                    for a in s_res.get("accounts", []):
                        db.add(Entity(case_id=case.id, category="SOCIAL_PROFILE", value=a, source_tool="sherlock"))
                        discovered_entities_text.append(f"Sherlock: {a}")

            # 3. Email module
            elif target_type == "EMAIL":
                if is_tool_enabled("holehe"):
                    h_res = await OSINTModules.run_holehe(target)
                    db.add(ScanLog(case_id=case.id, tool_name="holehe", status="COMPLETED", stdout_log=h_res["raw_log"], execution_time_sec=h_res["duration"]))
                    for p in h_res.get("platforms", []):
                        db.add(Entity(case_id=case.id, category="SERVICE_REGISTRATION", value=p, source_tool="holehe"))
                        discovered_entities_text.append(f"註冊平台: {p}")

            # 4. Phone module
            elif target_type == "PHONE":
                if is_tool_enabled("phoneinfoga"):
                    p_res = await OSINTModules.run_phoneinfoga(target)
                    db.add(ScanLog(case_id=case.id, tool_name="phoneinfoga", status="COMPLETED", stdout_log=p_res["raw_log"], execution_time_sec=p_res["duration"]))
                    for d in p_res.get("details", []):
                        db.add(Entity(case_id=case.id, category="PHONE_INTEL", value=d, source_tool="phoneinfoga"))
                        discovered_entities_text.append(f"門號情資: {d}")

            # 5. Domains, WAF, and Asset Module
            elif target_type == "DOMAIN":
                if is_tool_enabled("wafw00f"):
                    waf_res = await OSINTModules.run_wafw00f(target)
                    db.add(ScanLog(case_id=case.id, tool_name="wafw00f", status="COMPLETED", stdout_log=waf_res["raw_log"], execution_time_sec=waf_res["duration"]))
                    for w in waf_res.get("wafs", []):
                        db.add(Entity(case_id=case.id, category="WAF_FINGERPRINT", value=w, source_tool="wafw00f"))
                        discovered_entities_text.append(f"WAF protection: {w}")

                if is_tool_enabled("httpx"):
                    hx_res = await OSINTModules.run_httpx_probe(target)
                    db.add(ScanLog(case_id=case.id, tool_name="httpx", status="COMPLETED", stdout_log=hx_res["raw_log"], execution_time_sec=hx_res["duration"]))
                    for h in hx_res.get("results", []):
                        db.add(Entity(case_id=case.id, category="HTTP_PROBE", value=h, source_tool="httpx"))
                        discovered_entities_text.append(f"HTTP fingerprint: {h}")

                if is_tool_enabled("theHarvester"):
                    th_res = await OSINTModules.run_theharvester(target)
                    db.add(ScanLog(case_id=case.id, tool_name="theHarvester", status="COMPLETED", stdout_log=th_res["raw_log"], execution_time_sec=th_res["duration"]))

                if is_tool_enabled("amass"):
                    am_res = await OSINTModules.run_amass(target)
                    db.add(ScanLog(case_id=case.id, tool_name="amass", status="COMPLETED", stdout_log=am_res["raw_log"], execution_time_sec=am_res["duration"]))
                    for sub in am_res.get("subdomains", []):
                        db.add(Entity(case_id=case.id, category="SUBDOMAIN", value=sub, source_tool="amass"))
                        discovered_entities_text.append(f"Amass subdomain: {sub}")

                if is_tool_enabled("sublist3r"):
                    sub_res = await OSINTModules.run_sublist3r(target)
                    db.add(ScanLog(case_id=case.id, tool_name="sublist3r", status="COMPLETED", stdout_log=sub_res["raw_log"], execution_time_sec=sub_res["duration"]))
                    for sub in sub_res.get("subdomains", []):
                        db.add(Entity(case_id=case.id, category="SUBDOMAIN", value=sub, source_tool="sublist3r"))
                        discovered_entities_text.append(f"Sublist3r: {sub}")

                if is_tool_enabled("dnsrecon"):
                    dns_res = await OSINTModules.run_dnsrecon(target)
                    db.add(ScanLog(case_id=case.id, tool_name="dnsrecon", status="COMPLETED", stdout_log=dns_res["raw_log"], execution_time_sec=dns_res["duration"]))
                    for rec in dns_res.get("records", []):
                        db.add(Entity(case_id=case.id, category="DNS_RECORD", value=rec, source_tool="dnsrecon"))
                        discovered_entities_text.append(rec)

                if is_tool_enabled("whatweb"):
                    ww_res = await OSINTModules.run_whatweb(target)
                    db.add(ScanLog(case_id=case.id, tool_name="whatweb", status="COMPLETED", stdout_log=ww_res["raw_log"], execution_time_sec=ww_res["duration"]))
                    for t in ww_res.get("tech_stack", []):
                        db.add(Entity(case_id=case.id, category="TECH_STACK", value=t, source_tool="whatweb"))
                        discovered_entities_text.append(f"Website tech: {t}")

                if is_tool_enabled("nmap"):
                    nmap_res = await OSINTModules.run_nmap_quick(target)
                    db.add(ScanLog(case_id=case.id, tool_name="nmap", status="COMPLETED", stdout_log=nmap_res["raw_log"], execution_time_sec=nmap_res["duration"]))
                    for p in nmap_res.get("open_ports", []):
                        db.add(Entity(case_id=case.id, category="OPEN_PORT", value=p, source_tool="nmap"))
                        discovered_entities_text.append(f"Open port: {p}")

            # 6. AI Summary
            summary = await AIAnalyst.generate_dossier_summary(target, target_type, discovered_entities_text)
            case.ai_summary = summary
            case.status = CaseStatus.COMPLETED

        except Exception as e:
            case.status = CaseStatus.FAILED
            case.notes = f"Production malfunction: {str(e)}"

        await db.commit()

# ==================== Survey Management API ====================

@app.post("/api/investigate", summary="Establish and launch intelligence investigation mission")
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

@app.get("/api/cases", summary="Obtain/Search Investigation Case List")
async def list_cases(
    q: Optional[str] = Query(None, description="Search target or keywords"),
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

@app.get("/api/cases/{case_id}", summary="Obtain details of the investigated case and physical nodes")
async def get_case_detail(
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    result = await db.execute(select(Case).where(Case.id == case_id))
    case = result.scalar_one_or_none()
    if not case:
        raise HTTPException(status_code=404, detail="The specified investigation case could not be found.")

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

@app.delete("/api/cases/{case_id}", summary="Delete specific cases (限 ADMIN)")
async def delete_case(
    case_id: uuid.UUID,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles([UserRole.ADMIN]))
):
    case = await db.get(Case, case_id)
    if not case:
        raise HTTPException(status_code=404, detail="The case could not be found.")
    await db.delete(case)
    await db.commit()
    return {"message": "The case has been successfully deleted."}

# ==================== Front-end static page mounting ====================

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
frontend_dir = os.path.join(BASE_DIR, "frontend")

if os.path.exists(frontend_dir):
    app.mount("/static", StaticFiles(directory=frontend_dir), name="static")

    @app.get("/", include_in_schema=False)
    async def read_index():
        index_file = os.path.join(frontend_dir, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"message": "frontend/index.html Not yet established"}
