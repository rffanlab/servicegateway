from collections import defaultdict
from .schemas import Snapshot


def render(snapshot: Snapshot, policy: dict, digest: str, secret: str, admin_port=19092):
    """Render only validated structured data; never accept raw Nginx directives."""
    lines = [
        f"# servicegateway-digest {digest}", "user www-data;", "worker_processes auto;",
        "pid /run/servicegateway-edge/nginx.pid;", "error_log /srv/e5-logs/servicegateway/edge-error.log warn;",
        "events { worker_connections 4096; }", "http {", "  default_type application/octet-stream;",
        "  server_tokens off;", "  sendfile on;", "  keepalive_timeout 65;",
        "  map $http_upgrade $sg_connection { default upgrade; '' ''; }",
        "  map $host $sg_route { default '-'; }",
        "  log_format sg escape=json '{\"route\":\"$sg_route\",\"status\":$status,\"seconds\":$request_time,\"bytes\":$body_bytes_sent,\"request_id\":\"$request_id\"}';",
        "  access_log /srv/e5-logs/servicegateway/edge-access.log sg;",
        "  client_body_temp_path /var/lib/servicegateway/edge/client;",
        "  proxy_temp_path /var/lib/servicegateway/edge/proxy;",
        "  server { listen 127.0.0.1:19093; access_log off;",
        f"    location = /_sg/ready {{ return 200 '{digest}'; }}",
        "    location / { return 404; }", "  }",
    ]
    groups = defaultdict(list)
    for r in snapshot.routes:
        if not r.enabled:
            continue
        ident = r.id.replace("-", "_")
        lines.append(f"  upstream sg_{ident} {{")
        if r.balance != "round_robin":
            lines.append(f"    {r.balance};")
        for u in r.upstreams:
            lines.append(f"    server {u.key()} weight={u.weight} max_fails=3 fail_timeout=15s;")
        lines.extend(["    keepalive 16;", "  }"])
        if r.rate_per_second:
            lines.append(f"  limit_req_zone $binary_remote_addr zone=sg_{ident}:1m rate={r.rate_per_second}r/s;")
        groups[(r.listen_port, r.host)].append(r)
    for (port, host), routes in sorted(groups.items()):
        cert = routes[0].certificate
        lines += ["  server {", f"    listen {policy.get('listen_address', '0.0.0.0')}:{port}{' ssl' if cert else ''};", f"    server_name {host};"]
        if cert:
            lines += [f"    ssl_certificate /etc/servicegateway/certs/{cert}/fullchain.pem;", f"    ssl_certificate_key /etc/servicegateway/certs/{cert}/privkey.pem;", "    ssl_protocols TLSv1.2 TLSv1.3;"]
        lines += [f"    location = /_sg/ready {{ allow 127.0.0.1; deny all; access_log off; return 200 '{digest}'; }}"]
        for r in sorted(routes, key=lambda x: x.path):
            ident = r.id.replace("-", "_")
            if r.auth in ("session", "api_key"):
                lines += [f"    location = /_sg/auth/{r.id} {{", "      internal;", f"      proxy_pass http://127.0.0.1:{admin_port}/internal/auth;", "      proxy_pass_request_body off;", "      proxy_set_header Content-Length '';", f"      proxy_set_header X-SG-Secret {secret};", f"      proxy_set_header X-SG-Route {r.id};", "      proxy_set_header Cookie $http_cookie;", "      proxy_set_header X-Gateway-Key $http_x_gateway_key;", "      proxy_connect_timeout 3s;", "      proxy_read_timeout 5s;", "    }"]
            elif r.auth == "e5":
                lines += [f"    location = /_sg/auth/{r.id} {{", "      internal;", "      proxy_pass http://127.0.0.1:18090/api/auth/me;", "      proxy_pass_request_body off;", "      proxy_set_header Content-Length '';", "      proxy_set_header Cookie $http_cookie;", "      proxy_set_header X-Real-IP $remote_addr;", "    }"]
            lines += [f"    location ^~ {r.path} {{", f"      set $sg_route '{r.id}';"]
            for cidr in r.allow_cidrs or policy["allowed_cidrs"]:
                lines.append(f"      allow {cidr};")
            lines += ["      deny all;"]
            if r.auth != "public":
                lines.append(f"      auth_request /_sg/auth/{r.id};")
            if r.rate_per_second:
                lines += [f"      limit_req zone=sg_{ident} burst={r.burst} nodelay;", "      limit_req_status 429;"]
            lines += [f"      client_max_body_size {r.max_body_mb}m;", f"      proxy_pass http://sg_{ident}{'/' if r.strip_prefix else ''};", "      proxy_http_version 1.1;", "      proxy_set_header Host $http_host;", "      proxy_set_header X-Real-IP $remote_addr;", "      proxy_set_header X-Forwarded-For $remote_addr;", "      proxy_set_header X-Forwarded-Proto $scheme;", "      proxy_set_header X-Gateway-Key '';", "      proxy_set_header X-SG-Secret '';", "      proxy_set_header X-SG-Route '';", "      proxy_set_header X-Request-ID $request_id;", f"      proxy_set_header Connection {'$sg_connection' if r.websocket else chr(39)+chr(39)};"]
            if r.websocket:
                lines.append("      proxy_set_header Upgrade $http_upgrade;")
            lines += [f"      proxy_buffering {'on' if r.buffering else 'off'};", "      proxy_request_buffering off;", "      proxy_cache off;", "      proxy_connect_timeout 5s;", f"      proxy_read_timeout {r.timeout_seconds}s;", f"      proxy_send_timeout {r.timeout_seconds}s;", "      proxy_next_upstream error timeout;", "      proxy_next_upstream_tries 2;", "      add_header X-Request-ID $request_id always;", "    }"]
        if not any(r.path == "/" for r in routes):
            lines += ["    location / { return 404; }"]
        lines += ["  }"]
    lines += ["}", ""]
    return "\n".join(lines)
