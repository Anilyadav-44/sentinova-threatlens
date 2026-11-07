import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.v1.router import api_router
from app.core.config import settings
from app.core.database import Base, SessionLocal, engine
from app.core.middleware import AuditLoggingMiddleware
from app.core.websocket import ws_manager
from app.models.user import User
from app.seed.seed_data import seed_database

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("threatlens")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Initializing ThreatLens CTI Engine...")
    Base.metadata.create_all(bind=engine)

    # Auto-seed initial demo users and baseline telemetry if empty
    db = SessionLocal()
    try:
        user_count = db.query(User).count()
        if user_count == 0:
            logger.info("Empty database detected. Running initial ThreatLens seeding...")
            await seed_database()
    except Exception as e:
        logger.error(f"Error during auto-seed: {e}")
    finally:
        db.close()

    yield
    logger.info("ThreatLens Engine shutting down cleanly.")


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="Enterprise-grade Cyber Threat Intelligence (CTI) Platform for SOC operations, operating on STIX 2.1, TAXII, and MITRE ATT&CK standards.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# 1. Audit Logging Middleware (State changes POST, PUT, PATCH, DELETE)
app.add_middleware(AuditLoggingMiddleware)

# 2. CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 3. Include API v1 Router
app.include_router(api_router, prefix=settings.API_V1_STR)

# 4. Static Files & Dashboard UI
static_dir = os.path.join(os.path.dirname(__file__), "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", tags=["Dashboard UI"])
@app.get("/dashboard", tags=["Dashboard UI"])
def get_dashboard():
    index_file = os.path.join(static_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "ThreatLens CTI API is operational. Next.js dashboard available on port 3000."}


@app.get("/health", tags=["Health & Observability"])
def health_check():
    return {
        "status": "healthy",
        "service": "ThreatLens CTI API",
        "version": settings.VERSION,
        "database": "connected",
        "realtime_ws": "active"
    }


# 5. Real-Time WebSocket Gateway
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket, channel: str = Query("alerts.stream")):
    await ws_manager.connect(websocket, channel)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
