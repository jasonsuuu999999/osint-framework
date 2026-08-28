import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional
from sqlalchemy import String, Text, Integer, Float, DateTime, ForeignKey, Enum as SQLEnum
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship
import os
from dotenv import load_dotenv

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql+asyncpg://osint_user:osint_password@localhost:5432/osint_db")

engine = create_async_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
AsyncSessionLocal = async_sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)

class Base(DeclarativeBase):
    pass

class TargetType(str, Enum):
    PERSON = "PERSON"
    DOMAIN = "DOMAIN"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    UNKNOWN = "UNKNOWN"

class CaseStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"

class Case(Base):
    """Investigation Case/Target Entity"""
    __tablename__ = "cases"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    target_input: Mapped[str] = mapped_column(String(255), nullable=False)
    target_type: Mapped[TargetType] = mapped_column(SQLEnum(TargetType), default=TargetType.UNKNOWN)
    status: Mapped[CaseStatus] = mapped_column(SQLEnum(CaseStatus), default=CaseStatus.PENDING)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    entities: Mapped[List["Entity"]] = relationship("Entity", back_populates="case", cascade="all, delete-orphan")
    relations: Mapped[List["Relation"]] = relationship("Relation", back_populates="case", cascade="all, delete-orphan")
    scan_logs: Mapped[List["ScanLog"]] = relationship("ScanLog", back_populates="case", cascade="all, delete-orphan")

class Entity(Base):
    """Identified nodes(nodes)"""
    __tablename__ = "entities"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"))
    category: Mapped[str] = mapped_column(String(50), nullable=False)  # DOMAIN, IP, PERSON, EMAIL, PHONE, SOCIAL
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    raw_data: Mapped[dict] = mapped_column(JSONB, default=dict)
    source_tool: Mapped[str] = mapped_column(String(100), default="manual")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    case: Mapped["Case"] = relationship("Case", back_populates="entities")

class Relation(Base):
    """Relationships between entities (edges - used for graph drawing)"""
    __tablename__ = "relations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"))
    source_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"))
    target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("entities.id", ondelete="CASCADE"))
    relation_type: Mapped[str] = mapped_column(String(100), nullable=False)  # e.g., OWNS, REG_EMAIL, HAS_ACCOUNT
    confidence: Mapped[float] = mapped_column(Float, default=1.0)
    discovered_by: Mapped[str] = mapped_column(String(100), default="system")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    case: Mapped["Case"] = relationship("Case", back_populates="relations")

class ScanLog(Base):
    """Execution log"""
    __tablename__ = "scan_logs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    case_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("cases.id", ondelete="CASCADE"))
    tool_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(50), default="RUNNING")
    stdout_log: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    execution_time_sec: Mapped[float] = mapped_column(Float, default=0.0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    case: Mapped["Case"] = relationship("Case", back_populates="scan_logs")

class UserRole(str, Enum):
    ADMIN = "ADMIN"        # Manage users, delete cases, execute all tools
    ANALYST = "ANALYST"    # Create cases, execute tools, view reports
    VIEWER = "VIEWER"      # Can only view completed intelligence

class User(Base):
    """System User and Permission Model"""
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(50), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(SQLEnum(UserRole), default=UserRole.ANALYST)
    is_active: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
