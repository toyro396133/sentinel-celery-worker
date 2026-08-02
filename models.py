import os
from datetime import datetime
from sqlalchemy import create_engine, Column, String, Boolean, DateTime, JSON, Text, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://sentinel_admin:sentinel_secure_pass_2026@postgres:5432/sentinel_scanner")

Engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=Engine)
Base = declarative_base()

class TargetModel(Base):
    __tablename__ = "targets"

    id = Column(String, primary_key=True, index=True)
    domain = Column(String, unique=True, index=True, nullable=False)
    verification_token = Column(String, nullable=False)
    is_verified = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Historical scan attributes cached
    last_scan_mode = Column(String, nullable=True)
    last_scan_status = Column(String, default="IDLE")
    last_scan_time = Column(DateTime, nullable=True)
    last_scan_result = Column(JSON, nullable=True)
    last_ai_report = Column(Text, nullable=True)

def init_db():
    Base.metadata.create_all(bind=Engine)

if __name__ == "__main__":
    print("Initializing Database Schemas...")
    init_db()
    print("Database initializations completed.")
