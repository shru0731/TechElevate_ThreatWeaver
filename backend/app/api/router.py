from fastapi import APIRouter

from app.routers.analysis import router as analysis_router
from app.routers.auth import router as auth_router
from app.routers.demo import router as demo_router
from app.routers.exports import router as exports_router
from app.routers.graph import router as graph_router
from app.routers.health import router as health_router
from app.routers.ingestion import router as ingestion_router
from app.routers.jobs import router as jobs_router
from app.routers.monitors import router as monitors_router
from app.routers.paths import router as paths_router
from app.routers.remediation import router as remediation_router

api_router = APIRouter()
api_router.include_router(health_router, tags=["health"])
api_router.include_router(analysis_router, prefix="/analysis", tags=["analysis"])
api_router.include_router(ingestion_router, prefix="/ingestion", tags=["ingestion"])
api_router.include_router(jobs_router, prefix="/jobs", tags=["jobs"])
api_router.include_router(monitors_router, prefix="/monitors", tags=["monitors"])
api_router.include_router(exports_router, prefix="/exports", tags=["exports"])
api_router.include_router(graph_router, prefix="/graph", tags=["graph"])
api_router.include_router(paths_router, prefix="/paths", tags=["paths"])
api_router.include_router(remediation_router, prefix="/remediation", tags=["remediation"])
api_router.include_router(demo_router, tags=["demo"])
api_router.include_router(auth_router, prefix="/auth", tags=["auth"])
