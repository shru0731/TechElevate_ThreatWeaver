from functools import lru_cache

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Generator
from sqlalchemy.orm import Session

from app.database import SessionLocal, get_async_session_factory
from app.repositories.topology_repository import TopologyRepository
from app.services.analysis_service import AnalysisService
from app.services.attack_engine import AttackEngine
from app.services.export_service import ExportService
from app.services.graph_engine import GraphEngine
from app.services.ingestion.cisa_kev_client import CISAKEVClient
from app.services.ingestion_service import IngestionService
from app.services.job_service import JobService
from app.services.llm_module import LLMModule
from app.services.monitor_event_bus import MonitorEventBus, get_monitor_event_bus
from app.services.monitor_scheduler import MonitorScheduler, get_monitor_scheduler
from app.services.monitor_service import MonitorService
from app.core.config import get_settings
from app.services.ingestion.nmap_scanner import NmapScanner
from app.services.ingestion.nvd_client import NvdClient
from app.services.persistence_service import PersistenceService
from app.services.risk_engine import RiskEngine
from app.services.ingestion.shodan_enricher import ShodanEnricher


@lru_cache
def get_analysis_service() -> AnalysisService:
    settings = get_settings()
    return AnalysisService(
        topology_repository=TopologyRepository(),
        graph_engine=GraphEngine(),
        risk_engine=RiskEngine(),
        attack_engine=AttackEngine(max_hop_depth=settings.max_hop_depth),
        llm_module=LLMModule(),
    )

def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
async def get_async_db() -> AsyncGenerator[AsyncSession, None]:
    async_session_factory = get_async_session_factory()
    async with async_session_factory() as session:
        yield session


@lru_cache
def get_persistence_service() -> PersistenceService:
    return PersistenceService()


@lru_cache
def get_llm_module() -> LLMModule:
    return LLMModule()


@lru_cache
def get_job_service() -> JobService:
    return JobService(nvd_client=get_nvd_client())


@lru_cache
def get_nmap_scanner() -> NmapScanner:
    return NmapScanner(get_settings())


@lru_cache
def get_shodan_enricher() -> ShodanEnricher:
    return ShodanEnricher(get_settings())


@lru_cache
def get_ingestion_service() -> IngestionService:
    return IngestionService(
        nvd_client=get_nvd_client(),
        nmap_scanner=get_nmap_scanner(),
        shodan_enricher=get_shodan_enricher(),
        cisa_kev_client=CISAKEVClient(),
    )


@lru_cache
def get_monitor_service() -> MonitorService:
    return MonitorService()


@lru_cache
def get_monitor_event_bus_dependency() -> MonitorEventBus:
    return get_monitor_event_bus()


@lru_cache
def get_monitor_scheduler_dependency() -> MonitorScheduler:
    return get_monitor_scheduler()


@lru_cache
def get_export_service() -> ExportService:
    return ExportService(get_settings().export_storage_dir)


@lru_cache
def get_nvd_client() -> NvdClient:
    return NvdClient(get_settings())