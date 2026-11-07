import logging
import time
import uuid
from datetime import datetime, timezone
from typing import Callable, Optional

from jose import JWTError, jwt
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.audit import AuditLog

logger = logging.getLogger("threatlens.audit")

STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
EXCLUDED_AUDIT_PATHS = {"/health", "/docs", "/openapi.json", "/redoc", "/ws"}


def extract_resource_info(path: str) -> tuple[str, Optional[str]]:
    """
    Infers the resource_type and resource_id from the URL path.
    Example: /api/v1/indicators/abc-123 -> ("indicator", "abc-123")
    Example: /api/v1/indicators -> ("indicator", None)
    """
    segments = [s for s in path.strip("/").split("/") if s and s not in {"api", "v1"}]
    if not segments:
        return "system", None

    resource_type = segments[0]
    # Normalize plural to singular
    if resource_type.endswith("ies"):
        resource_type = resource_type[:-3] + "y"
    elif resource_type.endswith("s") and not resource_type.endswith("status"):
        resource_type = resource_type[:-1]

    resource_id = segments[1] if len(segments) > 1 else None
    return resource_type, resource_id


class AuditLoggingMiddleware(BaseHTTPMiddleware):
    """
    Production-grade security & audit middleware.
    1. Propagates or generates end-to-end tracing Correlation IDs (X-Correlation-ID).
    2. Intercepts all state-changing HTTP requests (POST, PUT, PATCH, DELETE).
    3. Records an append-only entry into `audit_log` with actor context, timestamp, and metadata.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Correlation ID propagation
        correlation_id = request.headers.get("x-correlation-id") or uuid.uuid4().hex
        request.state.correlation_id = correlation_id

        start_time = time.perf_counter()

        # Execute the request
        try:
            response: Response = await call_next(request)
        except Exception:
            raise
        finally:
            process_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # Inject correlation header into response
        response.headers["X-Correlation-ID"] = correlation_id

        # Only audit state-changing requests and ignore health/docs endpoints
        if request.method in STATE_CHANGING_METHODS and not any(request.url.path.startswith(p) for p in EXCLUDED_AUDIT_PATHS):
            self._log_audit_entry_sync(request, response.status_code, correlation_id, process_time_ms)

        return response

    def _log_audit_entry_sync(
        self,
        request: Request,
        status_code: int,
        correlation_id: str,
        duration_ms: float
    ) -> None:
        """Writes the append-only audit entry to the database."""
        # 1. Resolve Actor Identity from JWT Token if present
        actor_id: Optional[str] = None
        actor_username: str = "anonymous"

        auth_header = request.headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
            try:
                payload = jwt.decode(
                    token,
                    settings.SECRET_KEY,
                    algorithms=[settings.ALGORITHM]
                )
                actor_id = payload.get("sub")
                actor_username = payload.get("username") or payload.get("sub") or "authenticated_user"
            except JWTError:
                actor_username = "invalid_token_actor"

        # 2. Extract resource and action
        resource_type, resource_id = extract_resource_info(request.url.path)
        action_name = f"{request.method}_{resource_type.upper()}"
        client_ip = request.client.host if request.client else "unknown"

        # 3. Construct safe audit metadata
        audit_details = {
            "method": request.method,
            "path": request.url.path,
            "status_code": status_code,
            "client_ip": client_ip,
            "user_agent": request.headers.get("user-agent", "unknown"),
            "duration_ms": duration_ms,
            "query_params": dict(request.query_params)
        }

        # 4. Append to database in isolated session
        db = SessionLocal()
        try:
            entry = AuditLog(
                actor_id=actor_id,
                actor_username=actor_username,
                action=action_name,
                resource_type=resource_type,
                resource_id=resource_id,
                correlation_id=correlation_id,
                timestamp=datetime.now(timezone.utc),
                ip_address=client_ip,
                details=audit_details
            )
            db.add(entry)
            db.commit()
            logger.info(
                f"[AUDIT] {action_name} on {resource_type} (status {status_code}) "
                f"by {actor_username} [corr_id: {correlation_id}]"
            )
        except Exception as e:
            db.rollback()
            logger.error(f"Failed to record audit log: {e}")
        finally:
            db.close()
