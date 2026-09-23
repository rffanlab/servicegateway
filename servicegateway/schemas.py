import hashlib
import ipaddress
import json
import re
from typing import Literal
from urllib.parse import urlsplit
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

ID = r"^[a-z][a-z0-9-]{0,62}$"
UNIT = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,100}\.service$")
PATH = re.compile(r"^/[a-zA-Z0-9/_~-]*$")


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def endpoint(url: str) -> tuple[str, int]:
    u = urlsplit(url)
    if u.scheme != "http" or not u.hostname or u.username or u.password or u.query or u.fragment:
        raise ValueError("Only literal-IP HTTP URLs without credentials/query/fragment are supported")
    ipaddress.IPv4Address(u.hostname)
    if not PATH.fullmatch(u.path or "/"):
        raise ValueError("Invalid URL path")
    return u.hostname, u.port or 80


class ServiceSpec(Strict):
    id: str = Field(pattern=ID)
    name: str = Field(min_length=1, max_length=100)
    description: str = Field(default="", max_length=500)
    services: list[str] = Field(min_length=1, max_length=16)
    url: str = Field(default="", max_length=300)
    port: int = Field(ge=1, le=65535)
    health_url: str = Field(max_length=300)
    gpu: str = Field(default="CPU / API", max_length=100)
    accent: Literal["cyan", "violet", "amber", "rose"] = "cyan"
    warning: str = Field(default="停止或重启会中断当前任务。", max_length=300)

    @field_validator("services")
    @classmethod
    def valid_units(cls, values):
        if len(values) != len(set(values)) or any(not UNIT.fullmatch(x) for x in values):
            raise ValueError("Unit names must be unique, explicit .service names; templates and wildcards are forbidden")
        return values

    @field_validator("health_url")
    @classmethod
    def valid_health(cls, value):
        endpoint(value)
        return value

    @field_validator("url")
    @classmethod
    def valid_url(cls, value):
        if value:
            u = urlsplit(value)
            if u.scheme not in ("http", "https") or not u.hostname or u.username or u.password or any(ord(c) < 32 for c in value):
                raise ValueError("Service URL must be an HTTP(S) link without credentials")
        return value


class Upstream(Strict):
    address: str = "127.0.0.1"
    port: int = Field(ge=1024, le=65535)
    weight: int = Field(1, ge=1, le=100)

    @field_validator("address")
    @classmethod
    def ipv4(cls, value):
        return str(ipaddress.IPv4Address(value))

    def key(self):
        return f"{self.address}:{self.port}"


class UpstreamAuthSpec(Strict):
    mode: Literal["none", "route_secret"] = "none"


class RouteSpec(Strict):
    id: str = Field(pattern=ID)
    name: str = Field(min_length=1, max_length=100)
    service_id: str = Field(pattern=ID)
    listen_port: int = Field(default=443, ge=1, le=65535)
    host: str = Field(default="_", max_length=253)
    path: str = "/"
    strip_prefix: bool = False
    upstreams: list[Upstream] = Field(min_length=1, max_length=16)
    auth: Literal["session", "api_key", "e5", "public", "service_auth", "mtls", "mtls_or_api_key", "mtls_api_key", "wechat_user"] = "session"
    client_ca: str | None = Field(default=None, pattern=ID)
    upstream_auth: UpstreamAuthSpec = Field(default_factory=UpstreamAuthSpec)
    session_users: list[str] = Field(default_factory=list, max_length=200)
    business_roles: list[str] = Field(default_factory=list, max_length=32)
    max_connections: int = Field(16, ge=1, le=1024)
    enabled: bool = True
    websocket: bool = True
    buffering: bool = False
    timeout_seconds: int = Field(300, ge=5, le=7200)
    max_body_mb: int = Field(512, ge=1, le=4096)
    rate_per_second: int = Field(0, ge=0, le=10000)
    burst: int = Field(20, ge=1, le=10000)
    allow_cidrs: list[str] = Field(default_factory=list, max_length=32)
    certificate: str | None = Field(default=None, pattern=ID)
    balance: Literal["round_robin", "least_conn", "ip_hash"] = "round_robin"

    @field_validator("listen_port")
    @classmethod
    def business_port(cls, value):
        if value != 443 and value < 1024:
            raise ValueError("Business listeners use 443; high ports are LAN-only. Port 80 is redirect-only")
        return value

    @field_validator("host")
    @classmethod
    def valid_host(cls, value):
        value = value.lower()
        if value != "_" and (not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value) or ".." in value):
            raise ValueError("Use one exact hostname or _; no wildcards, regex or directives")
        return value

    @field_validator("path")
    @classmethod
    def valid_path(cls, value):
        if not PATH.fullmatch(value) or not value.endswith("/") or "//" in value or "/.." in value or value.startswith("/_sg"):
            raise ValueError("Prefix must start/end with / and cannot contain traversal, escapes or reserved /_sg")
        return value

    @field_validator("allow_cidrs")
    @classmethod
    def valid_cidrs(cls, values):
        return [str(ipaddress.IPv4Network(x, strict=False)) for x in values]

    @model_validator(mode="after")
    def unique_upstreams(self):
        if self.auth in ("mtls", "mtls_or_api_key", "mtls_api_key") and (not self.certificate or not self.client_ca):
            raise ValueError("mTLS-based auth requires a server certificate and a client CA identifier")
        if self.client_ca and self.auth not in ("mtls", "mtls_or_api_key", "mtls_api_key"):
            raise ValueError("client_ca is only valid for mTLS-based routes")
        if any(not re.fullmatch(r"[a-zA-Z0-9_.-]{1,64}", u) for u in self.session_users):
            raise ValueError("Invalid session username")
        if any(not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", role) for role in self.business_roles):
            raise ValueError("Invalid business user role")
        if len({x.key() for x in self.upstreams}) != len(self.upstreams):
            raise ValueError("Duplicate upstream")
        return self


class Snapshot(Strict):
    services: list[ServiceSpec] = Field(default_factory=list, max_length=200)
    routes: list[RouteSpec] = Field(default_factory=list, max_length=400)

    @model_validator(mode="after")
    def consistent(self):
        service_ids = {x.id for x in self.services}
        if len(service_ids) != len(self.services) or len({x.id for x in self.routes}) != len(self.routes):
            raise ValueError("Duplicate identifiers")
        matches, listeners, protocols = set(), {}, {}
        for r in self.routes:
            if r.service_id not in service_ids:
                raise ValueError(f"Unknown service: {r.service_id}")
            if not r.enabled:
                continue
            key = (r.listen_port, r.host, r.path)
            if key in matches:
                raise ValueError("Conflicting port/host/path")
            matches.add(key)
            protocol = protocols.setdefault(r.listen_port, bool(r.certificate))
            if protocol != bool(r.certificate):
                raise ValueError("A port cannot mix plaintext and TLS")
            listener = listeners.setdefault((r.listen_port, r.host), (r.certificate, r.client_ca))
            if listener != (r.certificate, r.client_ca):
                raise ValueError("Routes sharing a hostname and port must use identical server certificate and client CA")
        return self

    def digest(self):
        return hashlib.sha256(json.dumps(self.model_dump(), sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()


class PublishRequest(Strict):
    revision: int = Field(ge=0)
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    note: str = Field(default="", max_length=300)


class ActionRequest(Strict):
    action: Literal["start", "stop", "restart", "enable", "disable"]
    confirm: str = ""


class KeyRequest(Strict):
    name: str = Field(min_length=1, max_length=80)
    route_ids: list[str] = Field(default_factory=list, max_length=400)
    service_ids: list[str] = Field(default_factory=list, max_length=200)
    user_service_ids: list[str] = Field(default_factory=list, max_length=200)
    expires_days: int = Field(90, ge=1, le=365)

    @field_validator("route_ids", "service_ids", "user_service_ids")
    @classmethod
    def ids(cls, values):
        if any(not re.fullmatch(ID, x) for x in values):
            raise ValueError("Invalid scope identifier")
        return list(dict.fromkeys(values))
