from functools import lru_cache
from pathlib import Path

from pydantic import Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


BASE_DIR = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    app_name: str = "ThreatWeaver API"
    app_version: str = "1.0.0"
    api_v1_prefix: str = "/api/v1"
    debug: bool = False
    database_url: str = Field(
        default="postgresql://postgres:password@localhost:5432/threatweaver",
        alias="DATABASE_URL",
    )
    jwt_secret: str = Field(default="your_secret", alias="JWT_SECRET")
    jwt_algorithm: str = Field(default="HS256", alias="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(default=60, alias="ACCESS_TOKEN_EXPIRE_MINUTES")
    refresh_token_expire_days: int = Field(default=7, alias="REFRESH_TOKEN_EXPIRE_DAYS")
    request_id_header: str = Field(default="X-Request-ID", alias="REQUEST_ID_HEADER")
    export_storage_dir: Path = BASE_DIR / "generated_exports"
    task_queue_mode: str = Field(default="background", alias="TASK_QUEUE_MODE")
    redis_url: str = Field(default="redis://localhost:6379/0", alias="REDIS_URL")
    llm_provider: str = "gemini"
    enable_remote_llm: bool = False
    openai_api_key: str | None = Field(default=None, alias="OPENAI_API_KEY")
    gemini_api_key: str | None = Field(default=None, alias="GEMINI_API_KEY")
    gemini_model: str = "gemini-1.5-flash"
    groq_api_key: str | None = Field(default=None, alias="GROQ_API_KEY")
    groq_model: str = Field(default="llama-3.3-70b-versatile", alias="GROQ_MODEL")
    groq_base_url: str = Field(default="https://api.groq.com/openai/v1", alias="GROQ_BASE_URL")
    nvd_enabled: bool = Field(default=True, alias="NVD_ENABLED")
    nvd_api_key: str | None = Field(default=None, alias="NVD_API_KEY")
    nvd_base_url: str = Field(default="https://services.nvd.nist.gov/rest/json/cves/2.0", alias="NVD_BASE_URL")
    cisa_kev_enabled: bool = Field(default=False, alias="CISA_KEV_ENABLED")
    cisa_kev_url: str = Field(default="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json", alias="CISA_KEV_URL")
    shodan_enabled: bool = Field(default=False, alias="SHODAN_ENABLED")
    shodan_api_key: str | None = Field(default=None, alias="SHODAN_API_KEY")
    shodan_base_url: str = Field(default="https://api.shodan.io", alias="SHODAN_BASE_URL")
    nmap_binary_path: str = Field(default="/usr/bin/nmap", alias="NMAP_BINARY_PATH")
    nmap_default_args: str = Field(default="-sV -sC -O --open", alias="NMAP_DEFAULT_ARGS")
    nmap_scan_timeout: int = Field(default=300, alias="NMAP_SCAN_TIMEOUT")
    monitor_scheduler_enabled: bool = Field(default=False, alias="MONITOR_SCHEDULER_ENABLED")
    monitor_scheduler_poll_seconds: int = Field(default=30, alias="MONITOR_SCHEDULER_POLL_SECONDS")
    monitor_min_interval_seconds: int = Field(default=60, alias="MONITOR_MIN_INTERVAL_SECONDS")
    monitor_diff_risk_delta_threshold: float = Field(default=0.5, alias="MONITOR_DIFF_RISK_DELTA_THRESHOLD")
    llm_request_timeout_seconds: float = 5.0
    external_request_timeout_seconds: float = Field(default=5.0, alias="EXTERNAL_REQUEST_TIMEOUT_SECONDS")
    external_max_retries: int = Field(default=2, alias="EXTERNAL_MAX_RETRIES")
    default_topology_path: Path = BASE_DIR / "data" / "network.json"
    demo_topology_path: Path = BASE_DIR / "data" / "bank_network.json"
    default_max_depth: int = 5
    default_top_paths: int = 3
    max_hop_depth: int = Field(default=8, alias="MAX_HOP_DEPTH")
    async_analyze_threshold: int = Field(default=200, alias="ASYNC_ANALYZE_THRESHOLD")

    @field_validator("debug", mode="before")
    @classmethod
    def coerce_debug_value(cls, value: object) -> object:
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"release", "prod", "production", "false", "0", "no", "off"}:
                return False
            if normalized in {"debug", "dev", "development", "true", "1", "yes", "on"}:
                return True
        return value

    @field_validator("task_queue_mode")
    @classmethod
    def validate_task_queue_mode(cls, value: str) -> str:
        normalized = value.strip().lower()
        if normalized not in {"background", "celery"}:
            raise ValueError("TASK_QUEUE_MODE must be either 'background' or 'celery'")
        return normalized

    @field_validator("monitor_scheduler_poll_seconds", "monitor_min_interval_seconds")
    @classmethod
    def validate_positive_ints(cls, value: int) -> int:
        if value < 1:
            raise ValueError("Monitor scheduler settings must be positive integers")
        return value

    @field_validator("monitor_diff_risk_delta_threshold")
    @classmethod
    def validate_non_negative_threshold(cls, value: float) -> float:
        if value < 0:
            raise ValueError("MONITOR_DIFF_RISK_DELTA_THRESHOLD must be non-negative")
        return value

    @model_validator(mode="after")
    def validate_runtime_requirements(self) -> "Settings":
        if self.task_queue_mode == "celery" and not self.redis_url:
            raise ValueError("REDIS_URL is required when TASK_QUEUE_MODE=celery")

        if self.enable_remote_llm:
            provider = self.llm_provider.lower()
            if provider == "gemini" and not self.gemini_api_key:
                raise ValueError("GEMINI_API_KEY is required when ENABLE_REMOTE_LLM=true and LLM_PROVIDER=gemini")
            if provider == "groq" and not self.groq_api_key:
                raise ValueError("GROQ_API_KEY is required when ENABLE_REMOTE_LLM=true and LLM_PROVIDER=groq")
        return self

    model_config = SettingsConfigDict(
        env_file=BASE_DIR / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
        populate_by_name=True,
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
