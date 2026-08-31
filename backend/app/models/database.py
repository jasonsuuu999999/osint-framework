import os
import uuid
from enum import Enum
from datetime import datetime
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
from sqlalchemy import String, DateTime, ForeignKey, Text, Float, Integer, text
from sqlalchemy.dialects.postgresql import UUID, JSONB, ENUM as PG_ENUM
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql+asyncpg://osint_user:osint_password@localhost:5432/osint_db"
)

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

class TargetType(str, Enum):
    DOMAIN = "DOMAIN"
    PERSON = "PERSON"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    UNKNOWN = "UNKNOWN"

class CaseStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class UserRole(str, Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"

# PostgreSQL Enum definitions with auto type creation mapping
TargetTypeEnum = PG_ENUM(
    TargetType,
    name="targettype",
    create_type=False,
    values_callable=lambda obj: [e.value for e in obj]
)

CaseStatusEnum = PG_ENUM(
    CaseStatus,
    name="casestatus",
    create_type=False,
    values_callable=lambda obj: [e.value for e in obj]
)

UserRoleEnum = PG_ENUM(
    UserRole,
    name="userrole",
    create_type=False,
    values_callable=lambda obj: [e.value for e in obj]
)

class User(Base):
    """User account model for authentication and RBAC."""
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(UserRoleEnum, default=UserRole.ANALYST, nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

class Case(Base):
    """Investigation case container for entities and logs."""
    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    target_input: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[TargetType] = mapped_column(TargetTypeEnum, default=TargetType.UNKNOWN)
    status: Mapped[CaseStatus] = mapped_column(CaseStatusEnum, default=CaseStatus.PENDING)
    ai_summary: Mapped[str] = mapped_column(Text, nullable=True)
    notes: Mapped[str] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    entities: Mapped[list["Entity"]] = relationship(
        back_populates="case",
        cascade="all, delete-orphan",
        passive_deletes=True
    )
    scan_logs: Mapped[list["ScanLog"]] = relationship(
        back_populates="case",
        cascade="all, delete-orphan",
        passive_deletes=True
    )

class Entity(Base):
    """Discovered OSINT entity or asset node for Cytoscape visualization."""
    __tablename__ = "entities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    value: Mapped[str] = mapped_column(String(500), nullable=False)
    source_tool: Mapped[str] = mapped_column(String(100), nullable=False)
    properties: Mapped[dict] = mapped_column(JSONB, default=dict, server_default=text("'{}'::jsonb"))
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    case: Mapped["Case"] = relationship(back_populates="entities")

class ScanLog(Base):
    """Execution logs containing CLI syntax, terminal output, and duration."""
    __tablename__ = "scan_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    command_executed: Mapped[str] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="COMPLETED")
    stdout_log: Mapped[str] = mapped_column(Text, nullable=True)
    return_code: Mapped[int] = mapped_column(Integer, default=0)
    execution_time_sec: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    case: Mapped["Case"] = relationship(back_populates="scan_logs")

async def init_db():
    """Initializes schema, ensures custom enum types, and applies table migrations."""
    async with engine.begin() as conn:
        # 1. Pre-create PostgreSQL enum types if they do not exist
        await conn.execute(text("""
            DO $$ BEGIN
                CREATE TYPE userrole AS ENUM ('ADMIN', 'ANALYST', 'VIEWER');
            EXCEPTION WHEN duplicate_object THEN NULL;
            END $$;
        """))
        await conn.execute(text("""
            DO $$ BEGIN
                CREATE TYPE targettype AS ENUM ('DOMAIN', 'PERSON', 'EMAIL', 'PHONE', 'UNKNOWN');
            EXCEPTION WHEN duplicate_object THEN NULL;
            END $$;
        """))
        await conn.execute(text("""
            DO $$ BEGIN
                CREATE TYPE casestatus AS ENUM ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED');
            EXCEPTION WHEN duplicate_object THEN NULL;
            END $$;
        """))

        # 2. Create tables
        await conn.run_sync(Base.metadata.create_all)

        # 3. Apply schema migration patches for backward-compatibility
        await conn.execute(text("DO $$ BEGIN BEGIN ALTER TABLE entities ALTER COLUMN raw_data DROP NOT NULL; EXCEPTION WHEN undefined_column THEN NULL; END; END $$;"))
        await conn.execute(text("DO $$ BEGIN BEGIN ALTER TABLE entities ALTER COLUMN raw_data SET DEFAULT '{}'::jsonb; EXCEPTION WHEN undefined_column THEN NULL; END; END $$;"))
        await conn.execute(text("ALTER TABLE entities ADD COLUMN IF NOT EXISTS properties JSONB DEFAULT '{}'::jsonb;"))
        await conn.execute(text("ALTER TABLE scan_logs ADD COLUMN IF NOT EXISTS command_executed TEXT;"))
        await conn.execute(text("ALTER TABLE scan_logs ADD COLUMN IF NOT EXISTS return_code INTEGER DEFAULT 0;"))
