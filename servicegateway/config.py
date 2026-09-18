from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, model_validator


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SG_", env_file=".env", extra="ignore")
    database_url: str = "mysql+pymysql://servicegateway@127.0.0.1:3306/servicegateway?charset=utf8mb4"
    testing: bool = False
    secure_cookie: bool = True
    cookie_domain: str | None = None
    session_hours: int = Field(12, ge=1, le=168)
    agent_socket: str = "/run/servicegateway-agent/agent.sock"
    policy_file: str = "/etc/servicegateway/policy.json"
    auth_secret_file: str = "/etc/servicegateway/auth-secret"
    health_interval: int = Field(30, ge=5, le=3600)
    monitor_enabled: bool = True
    admin_port: int = Field(19092, ge=1024, le=65535)

    @model_validator(mode="after")
    def require_mysql(self):
        if not self.testing and not self.database_url.startswith("mysql+pymysql://"):
            raise ValueError("Production requires mysql+pymysql; SQLite is allowed only in isolated tests")
        return self

    def auth_secret(self) -> str:
        secret = Path(self.auth_secret_file).read_text().strip()
        if len(secret) < 32:
            raise ValueError("auth-secret must contain at least 32 characters")
        return secret
