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

CONFIG = Path("/etc/servicegateway/nginx.conf")
CERTS = Path("/etc/servicegateway/certs")
PROTECTED = {"servicegateway.service", "servicegateway-agent.service", "servicegateway-edge.service", "nginx.service", "mysql.service", "ssh.service", "sshd.service"}


def root_file(path):
    path = Path(path)
    s = path.lstat()
    if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or s.st_mode & 0o022:
        raise ValueError(f"Not a root-owned immutable regular file: {path}")
    for parent in path.parents:
        st = parent.lstat()
        if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
            raise ValueError(f"Unsafe parent directory: {parent}")
    return path


def command(args, timeout=25):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C.UTF-8"})
    if p.returncode:
        raise ValueError(f"{Path(args[0]).name} failed: {(p.stderr or p.stdout)[-400:]}")
    return p.stdout


def unit_info(unit):
    if unit in PROTECTED:
        raise ValueError("Gateway, database, SSH and system Nginx units cannot be controlled")
    raw = command(["/usr/bin/systemctl", "show", unit, "--property=Id,LoadState,ActiveState,SubState,UnitFileState,MainPID,FragmentPath,User"])
    info = dict(line.split("=", 1) for line in raw.splitlines() if "=" in line)
    if info.get("LoadState") != "loaded" or info.get("FragmentPath") != f"/etc/systemd/system/{unit}":
        raise ValueError("Unit must be installed directly in /etc/systemd/system")
    root_file(info["FragmentPath"])
    if info.get("User", "") in ("", "root", "0"):
        raise ValueError("Managed services must run as an explicit non-root user")
    return {"unit": unit, "active": info.get("ActiveState", "unknown"), "sub": info.get("SubState", "unknown"), "startup": info.get("UnitFileState", "unknown"), "pid": int(info.get("MainPID", "0"))}


def load_policy(settings):
    policy = json.loads(root_file(settings.policy_file).read_text())
    ipaddress.IPv4Address(policy.get("listen_address", "0.0.0.0"))
    policy["allowed_cidrs"] = [str(ipaddress.IPv4Network(x, strict=False)) for x in policy["allowed_cidrs"]]
    if not policy["allowed_cidrs"]:
        raise ValueError("At least one global allowed CIDR is required")
    ports = policy["listen_ports"]
    if any(type(p) is not int or not 1024 <= p <= 65535 or p in (18090, 19091, 19092, 19093) for p in ports):
        raise ValueError("Invalid/reserved listener port")
    policy.setdefault("services", {})
    policy["legacy_manifests"] = []
    legacy = Path("/etc/e5-business-manager/assets.d")
    if legacy.exists():
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
    return policy


def validate_service(spec, policy, inspect_units=True):
    grant = policy["services"].get(spec.id)
    if not grant or grant["units"] != spec.services or grant["health_url"] != spec.health_url:
        raise ValueError(f"{spec.id}: requires matching root approval or an existing E5 registry manifest")
    address, port = endpoint(spec.health_url)
    if f"{address}:{port}" not in grant["upstreams"]:
        raise ValueError("Health target is not approved")
    if inspect_units:
        for unit in spec.services:
            unit_info(unit)


def validate_snapshot(snapshot, policy, inspect_units=True):
    for service in snapshot.services:
        validate_service(service, policy, inspect_units)
    for route in snapshot.routes:
        if route.listen_port not in policy["listen_ports"]:
            raise ValueError(f"Listener port not approved: {route.listen_port}")
        allowed = policy["services"][route.service_id]["upstreams"]
        if any(up.key() not in allowed for up in route.upstreams):
            raise ValueError(f"Unapproved upstream for {route.id}")
        if route.auth == "public" and not policy.get("allow_public", False):
            raise ValueError("Public routes are disabled by root policy")
        networks = [ipaddress.IPv4Network(x) for x in policy["allowed_cidrs"]]
        if any(not any(ipaddress.IPv4Network(cidr).subnet_of(n) for n in networks) for cidr in route.allow_cidrs):
            raise ValueError("Route CIDRs cannot broaden the root policy")
        if route.certificate and inspect_units:
            root_file(CERTS / route.certificate / "fullchain.pem")
            root_file(CERTS / route.certificate / "privkey.pem")


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

    def live_digest(self):
        try:
            with self.opener.open("http://127.0.0.1:19093/_sg/ready", timeout=2) as response:
                result = response.read(100).decode()
                return result if re.fullmatch(r"[0-9a-f]{64}", result) else None
        except (OSError, URLError):
            return None

    def check_listeners(self, snapshot, digest):
        import http.client
        import ssl
        seen = set()
        for r in snapshot.routes:
            key = (r.listen_port, r.host)
            if not r.enabled or key in seen:
                continue
            seen.add(key)
            # Loopback-only readiness probe; verifies config identity, not PKI trust.
            conn = http.client.HTTPSConnection("127.0.0.1", r.listen_port, timeout=1, context=ssl._create_unverified_context()) if r.certificate else http.client.HTTPConnection("127.0.0.1", r.listen_port, timeout=1)
            try:
                conn.request("GET", "/_sg/ready", headers={"Host": r.host if r.host != "_" else "localhost"})
                resp = conn.getresponse()
                if resp.status != 200 or resp.read(100).decode() != digest:
                    return False
            except (OSError, http.client.HTTPException):
                return False
            finally:
                conn.close()
        return True

    def apply(self, snapshot, expected):
        with self.lock:
            policy = load_policy(self.settings)
            validate_snapshot(snapshot, policy)
            current = self.live_digest()
            if current != expected:
                raise ValueError("Live configuration changed or edge is down; reconcile before publishing")
            target = snapshot.digest()
            secret = self.settings.auth_secret()
            config = render(snapshot, policy, target, secret, self.settings.admin_port)
            old = root_file(CONFIG).read_text()
            candidate = CONFIG.with_name("candidate.conf")
            atomic_write(candidate, config)
            try:
                command(["/usr/sbin/nginx", "-t", "-c", str(candidate)])
            finally:
                candidate.unlink(missing_ok=True)
            if current == target and self.check_listeners(snapshot, target):
                return {"digest": target, "changed": False}
            atomic_write(CONFIG, config)
            try:
                command(["/usr/bin/systemctl", "reload", "servicegateway-edge.service"])
                for _ in range(20):
                    if self.live_digest() == target and self.check_listeners(snapshot, target):
                        return {"digest": target, "changed": True}
                    time.sleep(0.25)
                raise ValueError("New listeners/config fingerprint did not become ready")
            except Exception as exc:
                atomic_write(CONFIG, old)
                try:
                    command(["/usr/bin/systemctl", "reload", "servicegateway-edge.service"])
                    for _ in range(20):
                        if self.live_digest() == current:
                            raise RuntimeError("ROLLBACK_OK")
                        time.sleep(0.25)
                    raise ValueError("Rollback readiness timed out")
                except RuntimeError as result:
                    if str(result) == "ROLLBACK_OK":
                        raise ValueError(f"Publish failed; previous config restored: {type(exc).__name__}") from exc
                    raise
                except Exception as rollback:
                    raise ValueError("Publish and rollback verification failed; inspect edge locally") from rollback

    def dispatch(self, req):
        action = req.get("action")
        allowed = {"status": {"action"}, "inventory": {"action"}, "traffic": {"action"}, "validate": {"action", "snapshot"}, "apply": {"action", "snapshot", "expected"}, "service": {"action", "spec", "operation"}}
        if action not in allowed or set(req) - allowed[action]:
            raise ValueError("Unsupported agent request")
        if action == "status":
            value = self.live_digest()
            return {"running": bool(value), "digest": value}
        if action == "traffic":
            path = Path("/srv/e5-logs/servicegateway/edge-access.log")
            if not path.exists():
                return {"sample": [], "sampled_bytes": 0}
            with path.open("rb") as stream:
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
            return {"manifests": policy["legacy_manifests"], "grants": policy["services"], "listen_ports": policy["listen_ports"], "allow_public": policy.get("allow_public", False), "allowed_cidrs": policy["allowed_cidrs"]}
        if action in ("validate", "apply"):
            snap = Snapshot.model_validate(req["snapshot"])
            if action == "apply":
                return self.apply(snap, req["expected"])
            validate_snapshot(snap, policy)
            return {"digest": snap.digest(), "config": render(snap, policy, snap.digest(), "REDACTED", self.settings.admin_port)}
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
            result = {"ok": True, "data": self.server.broker.dispatch(json.loads(raw))}
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
    path.unlink(missing_ok=True)
    account = pwd.getpwnam("servicegateway")
    with Server(str(path), Handler) as server:
        os.chown(path, 0, account.pw_gid)
        os.chmod(path, 0o660)
        server.allowed_uid = account.pw_uid
        server.broker = Broker(settings)
        server.serve_forever()


if __name__ == "__main__":
    main()
