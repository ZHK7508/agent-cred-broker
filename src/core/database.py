import os
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql://postgres:dev@localhost:5432/broker",
)

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    pass


class AuditRow(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False)
    event_type = Column(String(16), nullable=False)
    principal = Column(String(256), nullable=False)
    agent_id = Column(String(256), nullable=False)
    action = Column(String(256), nullable=False, default="")
    resource = Column(Text, nullable=False, default="")
    purpose = Column(Text, nullable=False, default="")
    decision_reason = Column(Text, nullable=False, default="")
    token_jti = Column(String(64), nullable=True)
    prev_hash = Column(String(64), nullable=False)
    record_hash = Column(String(64), nullable=False)


def create_tables():
    Base.metadata.create_all(bind=engine)
