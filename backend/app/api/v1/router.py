from fastapi import APIRouter

from app.api.v1.alerts import router as alerts_router
from app.api.v1.audit import router as audit_router
from app.api.v1.auth import router as auth_router
from app.api.v1.export import router as export_router
from app.api.v1.feeds import router as feeds_router
from app.api.v1.incidents import router as incidents_router
from app.api.v1.indicators import router as indicators_router
from app.api.v1.search import router as search_router
from app.api.v1.stats import router as stats_router

api_router = APIRouter()
api_router.include_router(auth_router)
api_router.include_router(indicators_router)
api_router.include_router(alerts_router)
api_router.include_router(incidents_router)
api_router.include_router(feeds_router)
api_router.include_router(stats_router)
api_router.include_router(search_router)
api_router.include_router(export_router)
api_router.include_router(audit_router)
