from pathlib import Path
import re
from urllib.parse import urlsplit
from typing import Literal
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field, model_validator


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SG_", env_file=".env", extra="ignore")
    database_url: str = "mysql+pymysql://servicegateway@127.0.0.1:3306/servicegateway?charset=utf8mb4"
    testing: bool = False
    deployment_mode: Literal["remote", "lan"] = "remote"
    public_origin: str = "https://admin.invalid"
    session_idle_minutes: int = Field(30, ge=5, le=120)
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
        u = urlsplit(self.public_origin)
        if (u.scheme not in ("http", "https") or not u.hostname or u.username or u.password
                or u.path not in ("", "/") or u.query or u.fragment
                or not re.fullmatch(r"[a-zA-Z0-9.-]+", u.hostname)):
            raise ValueError("SG_PUBLIC_ORIGIN must be one exact HTTP(S) origin")
        if self.deployment_mode == "remote":
            if not self.secure_cookie or self.cookie_domain or u.scheme != "https":
                raise ValueError("Remote mode requires HTTPS, Secure host-only cookies")
        return self

    @property
    def cookie_name(self):
        return "__Host-sg_session" if self.deployment_mode == "remote" else "sg_session"

    def auth_secret(self) -> str:
        secret = Path(self.auth_secret_file).read_text().strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", secret):
            raise ValueError("auth-secret must be 32..128 URL-safe characters")
        return secret
