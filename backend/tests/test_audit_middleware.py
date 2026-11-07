import pytest
from starlette.testclient import TestClient

from app.core.database import Base, SessionLocal, engine
from app.core.security import create_access_token
from app.main import app
from app.models.audit import AuditLog
from app.models.user import User, UserRole


@pytest.fixture
def client_with_db():
    # Ensure all tables exist in the engine used by app and middleware
    Base.metadata.create_all(bind=engine)

    session = SessionLocal()
    admin = session.query(User).filter(User.username == "admin_test_sec").first()
    if not admin:
        admin = User(
            id="admin-uuid-test-1",
            email="admin_test_sec@threatlens.io",
            username="admin_test_sec",
            hashed_password="dummy_hash_for_test",
            role=UserRole.ADMIN,
            is_active=True
        )
        session.add(admin)
        session.commit()
    admin_id = admin.id
    session.close()

    test_client = TestClient(app)
    yield test_client, SessionLocal, admin_id


def test_correlation_id_and_audit_middleware(client_with_db):
    client, SessionClass, admin_id = client_with_db

    # 1. Health check (GET) should generate X-Correlation-ID
    res_health = client.get("/health")
    assert res_health.status_code == 200
    assert "x-correlation-id" in res_health.headers

    # 2. State-changing POST request with explicit correlation ID
    custom_corr_id = "test-corr-id-alpha-99"
    token = create_access_token(
        subject=admin_id,
        role=UserRole.ADMIN.value,
        extra_claims={"username": "admin_test_sec"}
    )

    res_post = client.post(
        "/api/v1/indicators",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Correlation-ID": custom_corr_id
        },
        json={
            "value": "203.0.113.195",
            "type": "ip",
            "severity_score": 85,
            "confidence": 90,
            "tlp": "amber",
            "description": "Suspicious scan source"
        }
    )
    # The response must preserve the custom correlation ID header
    assert res_post.headers.get("x-correlation-id") == custom_corr_id
    assert res_post.status_code in [201, 200, 409]

    # Verify append-only audit entry in DB
    db = SessionClass()
    audit = db.query(AuditLog).filter(AuditLog.correlation_id == custom_corr_id).first()
    assert audit is not None
    assert audit.action == "POST_INDICATOR"
    assert audit.resource_type == "indicator"
    assert audit.actor_username == "admin_test_sec"
    assert audit.details["method"] == "POST"
    assert audit.details["status_code"] in [201, 200, 409]
    db.close()
