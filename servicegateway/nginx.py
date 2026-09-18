from collections import defaultdict
from .schemas import Snapshot
from .ingress import render_frontdoor


def render(snapshot: Snapshot, policy: dict, digest: str, secret: str, admin_port=19092, generation=None):
    """Structured config only. No user-provided snippets, credentials or arbitrary paths."""
    generation = generation or digest
    lines = [
        f"# servicegateway-digest {digest}", "user www-data;", "worker_processes auto;",
        "pid /run/servicegateway-edge/nginx.pid;",
        "error_log /srv/e5-logs/servicegateway/edge-error.log crit;",
        "events { worker_connections 4096; }", "http {",
        "  default_type application/octet-stream;", "  server_tokens off;",
        "  sendfile on;", "  keepalive_timeout 30;", "  client_header_timeout 15s;",
        "  client_body_timeout 60s;", "  send_timeout 60s;", "  reset_timedout_connection on;",
        "  map $http_upgrade $sg_connection { default upgrade; '' ''; }",
        "  map $host $sg_route { default '-'; }",
        # Strip both current and LAN management cookies. Ambiguous duplicates drop all cookies.
        "  map $http_cookie $sg_cookie_step1 {", "    default $http_cookie;",
        '    "~^(?<sg_before1>.*?)(?:^|;)[[:space:]]*(?:__Host-sg_session|sg_session)=[^;]*(?<sg_after1>.*)$" "$sg_before1$sg_after1";',
        "  }",
        "  map $sg_cookie_step1 $sg_business_cookie {", "    default $sg_cookie_step1;",
        '    "~(?:^|;)[[:space:]]*(?:__Host-sg_session|sg_session)=" \"\";', "  }",
        '  map "$request_method:$http_sec_fetch_site" $sg_unsafe_site {',
        "    default 0;", '    "~^(POST|PUT|PATCH|DELETE):(cross-site|same-site)$" 1;', "  }",
        "  log_format sg escape=json '{\"route\":\"$sg_route\",\"status\":$status,\"seconds\":$request_time,\"bytes\":$body_bytes_sent,\"request_id\":\"$request_id\"}';",
        "  access_log /srv/e5-logs/servicegateway/edge-access.log sg;",
        "  client_body_temp_path /var/lib/servicegateway/edge/client;",
        "  proxy_temp_path /var/lib/servicegateway/edge/proxy;",
        "  server { listen 127.0.0.1:19093; access_log off;",
        f"    location = /_sg/ready {{ add_header X-SG-Generation {generation}; return 200 '{digest}'; }}",
        "    location / { return 404; }", "  }",
    ]
    if policy.get("remote_mode", False):
        lines += render_frontdoor(snapshot, policy, digest, generation, admin_port)
    groups = defaultdict(list)
    for r in snapshot.routes:
        if not r.enabled:
            continue
        ident = r.id.replace('-', '_')
        lines.append(f"  upstream sg_{ident} {{")
        if r.balance != 'round_robin':
            lines.append(f"    {r.balance};")
        for u in r.upstreams:
            lines.append(f"    server {u.key()} weight={u.weight} max_fails=3 fail_timeout=15s;")
        lines.extend(["    keepalive 16;", "  }"])
        lines.append(f"  limit_conn_zone $binary_remote_addr zone=sg_conn_{ident}:1m;")
        if r.rate_per_second:
            lines.append(f"  limit_req_zone $binary_remote_addr zone=sg_{ident}:1m rate={r.rate_per_second}r/s;")
        if r.auth == 'mtls':
            origin = f'https://{r.host}' + (f':{r.listen_port}' if r.listen_port != 443 else '')
            lines += [f"  map $http_origin $sg_origin_{ident} {{", "    default 0;", "    '' 1;", f"    '{origin}' 1;", "  }"]
        groups[(r.listen_port, r.host)].append(r)
    for (port, host), routes in sorted(groups.items()):
        cert, ca = routes[0].certificate, routes[0].client_ca
        address = policy.get('listen_address', '127.0.0.1')
        lines += ["  server {", f"    listen {address}:{port}{' ssl' if cert else ''};", f"    server_name {host};"]
        if host != '_':
            lines.append(f"    if ($host != {host}) {{ return 421; }}")
        if cert and policy.get("remote_mode", False):
            # SNI must select the same vhost whose HTTP policy is evaluated.
            lines.append(f"    if ($ssl_server_name != {host}) {{ return 421; }}")
        if cert:
            lines += [f"    ssl_certificate /etc/servicegateway/certs/{cert}/fullchain.pem;",
                      f"    ssl_certificate_key /etc/servicegateway/certs/{cert}/privkey.pem;",
                      "    ssl_protocols TLSv1.2 TLSv1.3;", "    ssl_session_tickets off;",
                      "    add_header Strict-Transport-Security 'max-age=31536000' always;"]
        if ca:
            lines += [f"    ssl_client_certificate /etc/servicegateway/certs/{ca}/ca.pem;",
                      f"    ssl_crl /etc/servicegateway/certs/{ca}/crl.pem;",
                      "    ssl_verify_client on;", "    ssl_verify_depth 2;",
                      "    ssl_session_cache off;"]
            if policy.get("remote_mode", False):
                lines.append("    if ($ssl_client_verify != SUCCESS) { return 403; }")
        # return executes before allow/deny, so restrict in that same rewrite phase.
        if not ca:
            lines += ["    location = /_sg/ready {", "      if ($remote_addr != 127.0.0.1) { return 404; }",
                      "      access_log off;", f"      add_header X-SG-Generation {generation};", f"      return 200 '{digest}';", "    }"]
        else:
            # Verify client cert even on this internal probe. Readiness does not bypass mTLS.
            lines += ["    location = /_sg/ready {", "      if ($remote_addr != 127.0.0.1) { return 404; }",
                      "      if ($ssl_client_verify != SUCCESS) { return 403; }",
                      "      access_log off;", f"      add_header X-SG-Generation {generation};", f"      return 200 '{digest}';", "    }"]
        for r in sorted(routes, key=lambda x: x.path):
            ident = r.id.replace('-', '_')
            if r.auth in ('session', 'api_key'):
                lines += [f"    location = /_sg/auth/{r.id} {{", "      internal;",
                          f"      proxy_pass http://127.0.0.1:{admin_port}/internal/auth;",
                          "      proxy_pass_request_body off;", "      proxy_set_header Content-Length '';",
                          "      proxy_set_header Host 127.0.0.1;", f"      proxy_set_header X-SG-Secret {secret};",
                          f"      proxy_set_header X-SG-Route {r.id};", f"      proxy_set_header X-SG-Digest {digest};",
                          "      proxy_set_header Cookie $http_cookie;", "      proxy_set_header X-Gateway-Key $http_x_gateway_key;",
                          "      proxy_connect_timeout 3s;", "      proxy_read_timeout 5s;", "    }"]
            elif r.auth == 'e5':
                lines += [f"    location = /_sg/auth/{r.id} {{", "      internal;",
                          "      proxy_pass http://127.0.0.1:18090/api/auth/me;", "      proxy_pass_request_body off;",
                          "      proxy_set_header Content-Length '';", "      proxy_set_header Cookie $http_cookie;",
                          "      proxy_set_header X-Real-IP $remote_addr;", "    }"]
            lines += [f"    location ^~ {r.path} {{", f"      set $sg_route '{r.id}';"]
            if r.auth == 'mtls':
                lines += [f"      if ($sg_origin_{ident} = 0) {{ return 403; }}",
                          "      if ($sg_unsafe_site = 1) { return 403; }"]
            for cidr in r.allow_cidrs or policy['allowed_cidrs']:
                lines.append(f"      allow {cidr};")
            lines += ["      deny all;", f"      limit_conn sg_conn_{ident} {r.max_connections};", "      limit_conn_status 429;"]
            if r.auth not in ('public', 'mtls'):
                lines.append(f"      auth_request /_sg/auth/{r.id};")
            if r.rate_per_second:
                lines += [f"      limit_req zone=sg_{ident} burst={r.burst} nodelay;", "      limit_req_status 429;"]
            lines += [f"      client_max_body_size {r.max_body_mb}m;",
                      f"      proxy_pass http://sg_{ident}{'/' if r.strip_prefix else ''};", "      proxy_http_version 1.1;",
                      "      proxy_set_header Host $http_host;", "      proxy_set_header X-Real-IP $remote_addr;",
                      "      proxy_set_header X-Forwarded-For $remote_addr;", "      proxy_set_header X-Forwarded-Proto $scheme;",
                      "      proxy_set_header Cookie $sg_business_cookie;"]
            for header in ('X-Gateway-Key', 'X-SG-Secret', 'X-SG-Digest', 'X-SG-Route', 'Forwarded', 'X-Forwarded-Host',
                           'X-Original-URL', 'X-Rewrite-URL', 'X-Auth-Request-User', 'X-Auth-Request-Email', 'X-Remote-User'):
                lines.append(f"      proxy_set_header {header} '';" )
            lines += ["      proxy_set_header X-Request-ID $request_id;",
                      "      proxy_set_header Connection " + ('$sg_connection;' if r.websocket else "'';"),
                      "      proxy_set_header Upgrade " + ('$http_upgrade;' if r.websocket else "'';"),
                      f"      proxy_buffering {'on' if r.buffering else 'off'};", "      proxy_request_buffering off;",
                      "      proxy_cache off;", "      proxy_connect_timeout 5s;",
                      f"      proxy_read_timeout {r.timeout_seconds}s;", f"      proxy_send_timeout {r.timeout_seconds}s;",
                      "      proxy_next_upstream error timeout;", "      proxy_next_upstream_tries 2;",
                      "      add_header X-Request-ID $request_id always;"]
            if cert:
                lines.append("      add_header Strict-Transport-Security 'max-age=31536000' always;")
            lines.append("    }")
        if not any(r.path == '/' for r in routes):
            lines.append("    location / { return 404; }")
        lines.append("  }")
    return '\n'.join(lines + ['}', ''])
