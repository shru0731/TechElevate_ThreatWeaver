from contextlib import asynccontextmanager
import logging
import uuid

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware

from app.api.router import api_router
from app.core.config import get_settings
from app.core.errors import install_exception_handlers
from app.core.logging import configure_logging
from app.core.request_context import set_request_id
from app.database import init_db
from app.services.monitor_scheduler import get_monitor_scheduler
from app.services.ingestion.cisa_kev_client import CISAKEVClient


def create_application() -> FastAPI:
    settings = get_settings()
    configure_logging()

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        init_db()
        settings.export_storage_dir.mkdir(parents=True, exist_ok=True)

        cisa_client = CISAKEVClient()
        if settings.cisa_kev_enabled:
            try:
                await cisa_client.refresh()
            except Exception as exc:
                logging.warning("Failed to refresh CISA KEV catalog at startup: %s", exc)

        scheduler = get_monitor_scheduler()
        await scheduler.start()
        yield
        await scheduler.stop()

    application = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        debug=settings.debug,
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # ---------------------  CORS – must be FIRST  ---------------------
    application.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ---------------------  Request ID middleware  -------------------
    @application.middleware("http")
    async def request_context_middleware(request: Request, call_next):
        request_id = request.headers.get(settings.request_id_header) or str(uuid.uuid4())
        set_request_id(request_id)
        request.state.request_id = request_id
        try:
            response = await call_next(request)
            response.headers[settings.request_id_header] = request_id
            return response
        finally:
            set_request_id(None)

    # ---------------------  Exception handlers  ---------------------
    install_exception_handlers(application)

    # ---------------------  Routes  ---------------------------------
    @application.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse(url=f"{settings.api_v1_prefix}/demo/dashboard", status_code=307)

    application.include_router(api_router, prefix=settings.api_v1_prefix)

    return application


app = create_application()