import enum

from sqlalchemy import JSON, Boolean, Column, DateTime, Enum, ForeignKey, String
from sqlalchemy.orm import relationship

from app.models.base import TimeStampedModel


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    SECURITY_ENGINEER = "security_engineer"
    INCIDENT_RESPONDER = "incident_responder"
    THREAT_HUNTER = "threat_hunter"
    SOC_ANALYST = "soc_analyst"
    EXECUTIVE = "executive"


class Role(TimeStampedModel):
    __tablename__ = "roles"

    name = Column(String(50), unique=True, index=True, nullable=False)
    description = Column(String(255), nullable=True)
    permissions = Column(JSON, default=list, nullable=False)  # e.g. ["indicators:read", "indicators:write"]

    users = relationship("User", back_populates="role_rel")


class User(TimeStampedModel):
    __tablename__ = "users"

    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(255), nullable=True)
    role = Column(Enum(UserRole), default=UserRole.SOC_ANALYST, nullable=False)
    role_id = Column(String(36), ForeignKey("roles.id", ondelete="SET NULL"), nullable=True)
    is_active = Column(Boolean, default=True, nullable=False)
    last_login = Column(DateTime(timezone=True), nullable=True)

    role_rel = relationship("Role", back_populates="users")
