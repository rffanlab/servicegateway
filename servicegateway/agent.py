"""Root-side, Unix-socket-only broker. No shell, arbitrary files or raw Nginx input."""
import json
import os
import pwd
import re
import secrets
import socket
import socketserver
import stat
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from urllib.request import ProxyHandler, build_opener
from urllib.error import URLError
import ipaddress
from .config import Settings
from .ipc import MAX_MESSAGE
from .nginx import render
from .schemas import ServiceSpec, Snapshot, endpoint
from .ingress import validate_ingress_policy, check_frontdoor, probe_ready
from .routing_policy import normalize_service_source_cidrs, validate_route_source_cidrs

CONFIG = Path("/etc/servicegateway/nginx.conf")
CERTS = Path("/etc/servicegateway/certs")
ACCESS_LOG = Path("/srv/e5-logs/servicegateway/edge-access.log")
PROTECTED = {"servicegateway.service", "servicegateway-agent.service", "servicegateway-edge.service", "nginx.service", "mysql.service", "ssh.service", "sshd.service"}


def root_file(path):
    path = Path(path)
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022 or s.st_nlink != 1:
        raise ValueError(f"Not a root-owned immutable regular file: {path}")
    for parent in path.parents:
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError(f"Unsafe parent directory: {parent}")
    return path


def command(args, timeout=25):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
    if p.returncode:
        raise ValueError(f"{Path(args[0]).name} failed (exit {p.returncode}); inspect the local service journal")
    return p.stdout


def unit_info(unit):
    if unit in PROTECTED:
        raise ValueError("Gateway, database, SSH and system Nginx units cannot be controlled")
    raw = command(["/usr/bin/systemctl", "show", unit, "--property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,FragmentPath,User,DropInPaths"])
    info = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    if info.get("LoadState") != "loaded" or info.get("FragmentPath") != f"/etc/systemd/system/{unit}":
        raise ValueError("Unit must be installed directly in /etc/systemd/system")
    if info.get("Id") != unit:
        raise ValueError("Unit aliases are not accepted")
    root_file(info["FragmentPath"])
    for dropin in info.get("DropInPaths", "").split():
        root_file(dropin)
    if info.get("User", "") in ("", "root", "0"):
        raise ValueError("Managed services must run as an explicit non-root user")
    return {"unit": unit, "active": info.get("ActiveState", "unknown"), "sub": info.get("SubState", "unknown"), "startup": info.get("UnitFileState", "unknown"), "pid": int(info.get("MainPID", "0"))}


def load_policy(settings):
    policy = json.loads(root_file(settings.policy_file).read_text())
    policy.setdefault("remote_mode", True)
    ipaddress.IPv4Address(policy.get("listen_address", "0.0.0.0"))
    policy["allowed_cidrs"] = [str(ipaddress.IPv4Network(x, strict=False)) for x in policy["allowed_cidrs"]]
    if not policy["allowed_cidrs"]:
        raise ValueError("At least one global allowed CIDR is required")
    ports = policy["listen_ports"]
    if any(type(p) is not int or not (p == 443 or 1024 <= p <= 65535) or p in (18090, 19091, 19092, 19093) for p in ports):
        raise ValueError("Invalid/reserved listener port")
    if policy.get("remote_mode", True):
        if policy.get("allow_public") or policy.get("include_legacy_registry"):
            raise ValueError("Remote policy forbids public auth and implicit legacy root grants")
        if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", policy.get("management_host", "")):
            raise ValueError("Remote policy requires an exact management_host")
    validate_ingress_policy(policy, inspect_files=False)
    policy.setdefault("services", {})
    policy["legacy_manifests"] = []
    legacy = Path("/etc/e5-business-manager/assets.d")
    if policy.get("include_legacy_registry", False) and legacy.exists():
        for path in sorted(legacy.glob("*.json"))[:200]:
            try:
                raw = json.loads(root_file(path).read_text())
                spec = ServiceSpec.model_validate({k: v for k, v in raw.items() if k in ServiceSpec.model_fields})
                host, port = endpoint(spec.health_url)
                if host != "127.0.0.1":
                    continue
                policy["services"].setdefault(spec.id, {"units": spec.services, "upstreams": [f"{host}:{port}"], "health_url": spec.health_url})
                policy["legacy_manifests"].append(spec.model_dump())
            except (OSError, ValueError):
                continue
    normalize_service_source_cidrs(policy)
    return policy


def validate_service(spec, policy, inspect_units=True):
    grant = policy["services"].get(spec.id)
    if not grant or grant["units"] != spec.services or grant["health_url"] != spec.health_url:
        raise ValueError(f"{spec.id}: requires matching root approval or an existing E5 registry manifest")
    address, port = endpoint(spec.health_url)
    if f"{address}:{port}" not in grant["upstreams"]:
        raise ValueError("Health target is not approved")
    # Reject metadata, unspecified, multicast, link-local and control-plane endpoints,
    # even if a malformed policy accidentally listed one.
    ip = ipaddress.ip_address(address)
    if ip.is_link_local or ip.is_unspecified or ip.is_multicast or f"{address}:{port}" in {
            "127.0.0.1:18090", "127.0.0.1:19091", "127.0.0.1:19092", "127.0.0.1:19093"}:
        raise ValueError("Sensitive health target is forbidden")
    if inspect_units:
        for unit in spec.services:
            unit_info(unit)


def validate_snapshot(snapshot, policy, inspect_units=True):
    validate_ingress_policy(policy, inspect_files=inspect_units)
    for service in snapshot.services:
        validate_service(service, policy, inspect_units)
    for route in snapshot.routes:
        if policy.get("remote_mode", True):
            if not policy.get("ingress_enabled", False) or route.listen_port != 443:
                raise ValueError("Remote business routes require the enabled unified 443 ingress")
            if route.auth not in ("api_key", "mtls", "mtls_or_api_key", "mtls_api_key") or not route.certificate or route.host == "_":
                raise ValueError("Remote routes require exact host, TLS and API key, mTLS, or certificate/API-key fallback")
            if route.host == policy.get("management_host"):
                raise ValueError("Business routes must not use the management hostname")
            if route.rate_per_second < 1:
                raise ValueError("Remote routes must configure a positive rate limit")
        if route.listen_port not in policy["listen_ports"]:
            raise ValueError(f"Listener port not approved: {route.listen_port}")
        for upstream in route.upstreams:
            ip = ipaddress.ip_address(upstream.address)
            if ip.is_link_local or ip.is_unspecified or ip.is_multicast:
                raise ValueError("Metadata, link-local and special upstreams are forbidden")
            if ip.is_loopback and upstream.port in (18090, 19091, 19092, 19093):
                raise ValueError("Control-plane upstreams are forbidden")
        allowed = policy["services"][route.service_id]["upstreams"]
        if any(up.key() not in allowed for up in route.upstreams):
            raise ValueError(f"Unapproved upstream for {route.id}")
        if route.auth == "public" and not policy.get("allow_public", False):
            raise ValueError("Public routes are disabled by root policy")
        validate_route_source_cidrs(policy, route)
        if route.client_ca and inspect_units:
            root_file(CERTS / route.client_ca / "ca.pem")
            root_file(CERTS / route.client_ca / "crl.pem")
            root_file(CERTS / route.client_ca / "probe.crt")
            key = root_file(CERTS / route.client_ca / "probe.key")
            if key.stat().st_mode & 0o077:
                raise ValueError("Probe private key must be mode 0600")
        if route.certificate and inspect_units:
            root_file(CERTS / route.certificate / "fullchain.pem")
            key = root_file(CERTS / route.certificate / "privkey.pem")
            if key.stat().st_mode & 0o077:
                raise ValueError("Server private key must be mode 0600")


def atomic_write(path, data, mode=0o600):
    fd, name = tempfile.mkstemp(prefix=".sg-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(name, mode)
        os.replace(name, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class Broker:
    def __init__(self, settings):
        self.settings = settings
        self.lock = threading.RLock()
        self.opener = build_opener(ProxyHandler({}))

    def live_identity(self):
        try:
            with self.opener.open("http://127.0.0.1:19093/_sg/ready", timeout=2) as response:
                result = response.read(100).decode()
                return {"digest": result, "generation": response.headers.get("X-SG-Generation")} if re.fullmatch(r"[0-9a-f]{64}", result) else {}
        except (OSError, URLError):
            return {}

    def live_digest(self):
        return self.live_identity().get("digest")

    def recover_interrupted(self):
        from . import recovery
        with self.lock:
            from . import certificates, pki_maintenance
            if pki_maintenance.restore_pending():
                command(["/usr/sbin/nginx", "-t", "-c", str(CONFIG)])
                command(["/usr/bin/systemctl", "reload", "servicegateway-edge.service"])
                pki_maintenance.finish()
            if certificates.restore_files():
                command(["/usr/sbin/nginx", "-t", "-c", str(CONFIG)])
                command(["/usr/bin/systemctl", "reload", "servicegateway-edge.service"])
                certificates.finish()
            record = recovery.restore_disk()
            if not record:
                return
            command(["/usr/bin/systemctl", "reload", "servicegateway-edge.service"])
            for _ in range(40):
                if self.live_identity() == record:
                    recovery.finish()
                    return
                time.sleep(.25)
            raise ValueError("Interrupted publish restoration is unverified; keeping journal")

    def check_listeners(self, snapshot, digest, generation=None, policy=None):
        policy = policy or load_policy(self.settings)
        if policy.get("remote_mode", True) and not check_frontdoor(policy, digest, generation):
            return False
        seen = set()
        for route in snapshot.routes:
            key = (route.listen_port, route.host)
            if not route.enabled or key in seen:
                continue
            seen.add(key)
            if not probe_ready(route.host, route.listen_port, route.certificate, route.client_ca,
                               digest, generation, require_sni=policy.get("remote_mode", True)):
                return False
        return True

    def apply(self, snapshot, expected, generation):
        with self.lock:
            from .certificates import JOURNAL as tls_journal
            from .pki_maintenance import JOURNAL as crl_journal
            if tls_journal.exists() or crl_journal.exists():
                raise ValueError("Certificate recovery must complete before publication")
            policy = load_policy(self.settings)
            validate_snapshot(snapshot, policy)
            identity = self.live_identity()
            current = identity.get("digest")
            if current != expected:
                raise ValueError("Live configuration changed or edge is down; reconcile before publishing")
            target = snapshot.digest()
            secret = self.settings.auth_secret()
            if not re.fullmatch(r"[0-9a-f]{32}", generation):
                raise ValueError("Invalid release generation")
            from .upstream_secrets import resolve as resolve_upstream_secrets
            route_secrets, _ = resolve_upstream_secrets(snapshot, strict=True, preview=False)
            config = render(snapshot, policy, target, secret, self.settings.admin_port, generation, upstream_secrets=route_secrets)
            old = root_file(CONFIG).read_text()
            candidate = CONFIG.with_name("candidate.conf")
            atomic_write(candidate, config)
            try:
                command(["/usr/sbin/nginx", "-t", "-c", str(candidate)])
            finally:
                candidate.unlink(missing_ok=True)
            from . import recovery
            recovery.begin(old, current, identity.get("generation"))
            atomic_write(CONFIG, config)
            try:
                command(["/usr/bin/systemctl", "reload", "servicegateway-edge.service"])
                for _ in range(20):
                    if self.live_identity() == {"digest": target, "generation": generation} and self.check_listeners(snapshot, target, generation, policy):
                        recovery.finish()
                        return {"digest": target, "changed": True}
                    time.sleep(0.25)
                raise ValueError("New listeners/config fingerprint did not become ready")
            except Exception as exc:
                try:
                    self.recover_interrupted()
                except Exception as rollback:
                    raise ValueError("Publish and rollback verification failed; journal retained for local recovery") from rollback
                raise ValueError("Publish failed; previous configuration restored") from exc

    def dispatch(self, req):
        action = req.get("action")
        allowed = {"database-status": {"action"}, "database-create": {"action", "spec"}, "database-credentials": {"action", "service_id", "account"}, "pki-status": {"action"}, "client-bundle": {"action"}, "install-crl": {"action", "pem"}, "reload-tls": {"action"}, "sync-certificates": {"action"}, "bootstrap-ingress": {"action"}, "status": {"action"}, "inventory": {"action"}, "traffic": {"action"}, "validate": {"action", "snapshot"}, "apply": {"action", "snapshot", "expected", "generation"}, "service": {"action", "spec", "operation"}}
        if action not in allowed or set(req) - allowed[action]:
            raise ValueError("Unsupported agent request")
        if action in ("database-status", "database-create", "database-credentials"):
            from . import business_databases as databases
            if action == "database-status":
                return databases.status()
            if action == "database-credentials":
                return databases.credentials(req["service_id"], req["account"])
            return databases.create(req["spec"], load_policy(self.settings))
        if action in ("pki-status", "client-bundle", "install-crl"):
            from . import pki_maintenance as pki
            if action == "pki-status":
                return pki.public_status()
            if action == "client-bundle":
                return pki.bundle_payload()
            return pki.install_crl(self, req["pem"])
        if action in ("sync-certificates", "reload-tls"):
            from .certificates import sync
            return sync(self, force=action == "reload-tls")
        if action == "bootstrap-ingress":
            with self.lock:
                policy = load_policy(self.settings)
                if not policy.get("remote_mode", True) or not policy.get("ingress_enabled", False):
                    raise ValueError("Configure and explicitly enable remote ingress in root policy first")
                empty = Snapshot()
                if self.live_digest() != empty.digest():
                    raise ValueError("Bootstrap requires an empty live gateway; use normal publication for existing services")
                return self.apply(empty, empty.digest(), secrets.token_hex(16))
        if action == "status":
            from . import recovery
            with self.lock:
                from .certificates import JOURNAL as tls_journal
                from .pki_maintenance import JOURNAL as crl_journal
                if recovery.pending() or tls_journal.exists() or crl_journal.exists():
                    raise ValueError("Publish recovery is pending; do not reconcile against an intermediate state")
                identity = self.live_identity()
                return {"running": bool(identity), "digest": identity.get("digest"), "generation": identity.get("generation")}
        if action == "traffic":
            path = ACCESS_LOG
            if not path.exists():
                return {"sample": [], "sampled_bytes": 0}
            with root_file(path).open("rb") as stream:
                size = stream.seek(0, 2)
                stream.seek(max(0, size - 262144))
                raw = stream.read(262144)
            items = []
            for line in raw.splitlines():
                try:
                    row = json.loads(line)
                    items.append({k: row.get(k) for k in ("route", "status", "seconds", "bytes", "request_id")})
                except ValueError:
                    pass
            return {"sample": items[-200:], "sampled_bytes": len(raw)}
        policy = load_policy(self.settings)
        if action == "inventory":
            return {"remote_mode": policy.get("remote_mode", True), "ingress_enabled": policy.get("ingress_enabled", False), "manifests": policy["legacy_manifests"], "grants": policy["services"], "listen_ports": policy["listen_ports"], "allow_public": policy.get("allow_public", False), "allowed_cidrs": policy["allowed_cidrs"]}
        if action in ("validate", "apply"):
            snap = Snapshot.model_validate(req["snapshot"])
            if action == "apply":
                return self.apply(snap, req["expected"], req["generation"])
            validate_snapshot(snap, policy)
            from .upstream_secrets import resolve as resolve_upstream_secrets
            preview_secrets, missing = resolve_upstream_secrets(snap, strict=False, preview=True)
            return {"digest": snap.digest(), "config": render(snap, policy, snap.digest(), "REDACTED", self.settings.admin_port, upstream_secrets=preview_secrets),
                    "missing_upstream_secrets": missing}
        spec = ServiceSpec.model_validate(req["spec"])
        validate_service(spec, policy)
        operation = req["operation"]
        if operation not in ("status", "start", "stop", "restart", "enable", "disable"):
            raise ValueError("Unsupported lifecycle action")
        with self.lock:
            if operation in ("stop", "restart"):
                for unit in reversed(spec.services):
                    command(["/usr/bin/systemctl", "stop", unit])
            if operation in ("start", "restart", "enable", "disable"):
                verb = "start" if operation == "restart" else operation
                for unit in spec.services:
                    if verb in ("enable", "disable"):
                        # systemctl enable would write from this sandbox. PID1 owns this action.
                        method = "EnableUnitFiles" if verb == "enable" else "DisableUnitFiles"
                        args = ["/usr/bin/busctl", "call", "org.freedesktop.systemd1",
                                "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", method,
                                "asbb" if verb == "enable" else "asb", "1", unit, "false"]
                        if verb == "enable":
                            args.append("false")
                        command(args)
                        command(["/usr/bin/systemctl", "daemon-reload"])
                    else:
                        command(["/usr/bin/systemctl", verb, unit])
            units = [unit_info(unit) for unit in spec.services]
        active = [x["active"] == "active" for x in units]
        enabled = [x["startup"] == "enabled" for x in units]
        state = "running" if all(active) else "partial" if any(active) else "stopped"
        if any(x["active"] == "failed" for x in units):
            state = "failed"
        return {"units": units, "state": state, "startup": "enabled" if all(enabled) else "partial" if any(enabled) else "disabled"}


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, *args, **kwargs):
        self.capacity = threading.BoundedSemaphore(16)
        super().__init__(*args, **kwargs)

    def process_request(self, request, client_address):
        if not self.capacity.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.capacity.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.capacity.release()


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(100)
        _, uid, _ = struct.unpack("3i", self.connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
        if uid not in (0, self.server.allowed_uid):
            return
        raw = self.rfile.readline(MAX_MESSAGE + 1)
        try:
            if len(raw) > MAX_MESSAGE or not raw.endswith(b"\n"):
                raise ValueError("Request exceeds limit")
            request = json.loads(raw)
            if request.get("action") in ("bootstrap-ingress", "sync-certificates", "reload-tls", "install-crl") and uid != 0:
                raise ValueError("Ingress/certificate maintenance is local-root-only")
            result = {"ok": True, "data": self.server.broker.dispatch(request)}
        except Exception as exc:
            message = str(exc) if isinstance(exc, ValueError) else type(exc).__name__
            # Never include an auth-secret, password, cookie or entire input.
            secret = self.server.broker.settings.auth_secret()
            result = {"ok": False, "error": message.replace(secret, "[redacted]")[:500]}
        out = json.dumps(result).encode() + b"\n"
        if len(out) > MAX_MESSAGE:
            out = b'{"ok":false,"error":"Response exceeds limit"}\n'
        self.wfile.write(out)


def main():
    if os.geteuid() != 0:
        raise SystemExit("Agent must run under its dedicated root systemd unit")
    settings = Settings()
    load_policy(settings)
    root_file(settings.auth_secret_file)
    settings.auth_secret()
    path = Path(settings.agent_socket)
    account = pwd.getpwnam("servicegateway")
    parent = path.parent.lstat()
    if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_gid != account.pw_gid
            or stat.S_IMODE(parent.st_mode) != 0o750):
        raise SystemExit("Agent RuntimeDirectory must be root:servicegateway 0750; install the updated unit")
    path.unlink(missing_ok=True)
    with Server(str(path), Handler) as server:
        os.chown(path, 0, account.pw_gid)
        os.chmod(path, 0o660)
        server.allowed_uid = account.pw_uid
        server.broker = Broker(settings)
        server.broker.recover_interrupted()
        server.serve_forever()


if __name__ == "__main__":
    main()
