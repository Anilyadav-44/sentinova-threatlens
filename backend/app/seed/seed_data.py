import asyncio

from sqlalchemy.orm import Session

from app.core.database import Base, SessionLocal, engine
from app.core.security import get_password_hash
from app.ingestion.manager import ingestion_manager
from app.models.security_event import SecurityEvent
from app.models.user import User, UserRole

DEFAULT_PASSWORD = "ThreatLens@2026!"

PERSONAS = [
    {
        "username": "ciso",
        "email": "rachel.adeyemi@sentinova.internal",
        "full_name": "Rachel Adeyemi",
        "role": UserRole.EXECUTIVE,
    },
    {
        "username": "analyst",
        "email": "priya.nair@sentinova.internal",
        "full_name": "Priya Nair",
        "role": UserRole.SOC_ANALYST,
    },
    {
        "username": "ir_lead",
        "email": "daniel.okafor@sentinova.internal",
        "full_name": "Daniel Okafor",
        "role": UserRole.INCIDENT_RESPONDER,
    },
    {
        "username": "hunter",
        "email": "meilin.tan@sentinova.internal",
        "full_name": "Mei Lin Tan",
        "role": UserRole.THREAT_HUNTER,
    },
    {
        "username": "admin",
        "email": "alex.rivera@sentinova.internal",
        "full_name": "Alex Rivera",
        "role": UserRole.ADMIN,
    },
    {
        "username": "engineer",
        "email": "sam.chen@sentinova.internal",
        "full_name": "Sam Chen",
        "role": UserRole.SECURITY_ENGINEER,
    },
]

INTERNAL_SECURITY_EVENTS = [
    {
        "source_system": "Palo Alto NGFW (Perimeter)",
        "event_type": "outbound_connection",
        "source_ip": "10.0.12.44",
        "destination_ip": "185.220.101.4",
        "domain": None,
        "url": None,
        "file_hash": None,
        "user_identity": "jdoe@sentinova.internal",
        "raw_event": {"port": 22, "protocol": "TCP", "bytes_sent": 14200, "action": "alert"}
    },
    {
        "source_system": "CrowdStrike Falcon EDR",
        "event_type": "process_execution",
        "source_ip": "10.0.15.109",
        "destination_ip": None,
        "domain": None,
        "url": None,
        "file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "user_identity": "finance-admin@sentinova.internal",
        "raw_event": {"process_name": "svchost_update.exe", "path": "C:\\Windows\\Temp\\", "action": "blocked"}
    },
    {
        "source_system": "Cisco Umbrella DNS Resolver",
        "event_type": "dns_lookup",
        "source_ip": "10.0.8.21",
        "destination_ip": "91.240.118.23",
        "domain": "update-windows-service-catalog.com",
        "url": None,
        "file_hash": None,
        "user_identity": "dev-build-node@sentinova.internal",
        "raw_event": {"query_type": "A", "response_code": "NOERROR"}
    },
    {
        "source_system": "Squid Secure Web Gateway",
        "event_type": "http_request",
        "source_ip": "10.0.4.52",
        "destination_ip": "185.196.8.212",
        "domain": None,
        "url": "http://185.196.8.212/bins/arm7",
        "file_hash": None,
        "user_identity": "iot-gateway-01",
        "raw_event": {"status_code": 200, "user_agent": "Wget/1.20.3"}
    }
]

async def seed_database():
    print("[ThreatLens] Creating database tables...")
    Base.metadata.create_all(bind=engine)
    db: Session = SessionLocal()

    try:
        # 1. Seed Users
        print("[ThreatLens] Seeding PRD Persona Users...")
        for p in PERSONAS:
            existing = db.query(User).filter(User.username == p["username"]).first()
            if not existing:
                user = User(
                    username=p["username"],
                    email=p["email"],
                    full_name=p["full_name"],
                    role=p["role"],
                    hashed_password=get_password_hash(DEFAULT_PASSWORD),
                    is_active=True
                )
                db.add(user)
        db.commit()

        # 2. Seed Internal Security Events for Correlation
        print("[ThreatLens] Seeding internal telemetry logs for correlation...")
        if db.query(SecurityEvent).count() == 0:
            for ev in INTERNAL_SECURITY_EVENTS:
                event = SecurityEvent(
                    source_system=ev["source_system"],
                    event_type=ev["event_type"],
                    source_ip=ev["source_ip"],
                    destination_ip=ev["destination_ip"],
                    domain=ev["domain"],
                    url=ev["url"],
                    file_hash=ev["file_hash"],
                    user_identity=ev["user_identity"],
                    raw_event=ev["raw_event"],
                    is_correlated=False
                )
                db.add(event)
            db.commit()

        # 3. Seed Feeds & Ingest Initial Intelligence
        print("[ThreatLens] Ingesting threat intelligence across all 6 feeds...")
        await ingestion_manager.poll_all_enabled_feeds(db)

        print("[ThreatLens] Seed complete! Ready for analyst operations.")
    finally:
        db.close()

if __name__ == "__main__":
    asyncio.run(seed_database())
