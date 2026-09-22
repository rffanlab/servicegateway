"""Single owner for public 80/443; the protected management vhost is not a user route."""
import http.client
import ipaddress
import re
import socket
import ssl
from .acme import http_vhost

CERT_ID = re.compile(r"^[a-z][a-z0-9-]{0,62}$")


def validate_ingress_policy(policy, inspect_files=True):
    if not policy.get("remote_mode", True):
        return
    if policy.get("listen_ports") != [443]:
        raise ValueError("Remote policy allows business port 443 only; 80 is managed redirect-only")
    if policy.get("listen_address", "127.0.0.1") not in ("127.0.0.1", "0.0.0.0"):
        raise ValueError("Use loopback for staging or 0.0.0.0 after explicit network approval")
    if type(policy.get("ingress_enabled", False)) is not bool:
        raise ValueError("ingress_enabled must be a boolean")
    if type(policy.get("acme_enabled", False)) is not bool:
        raise ValueError("acme_enabled must be a boolean")
    ip_filter = policy.get("management_ip_filter", True)  # Preserve legacy policies.
    if type(ip_filter) is not bool:
        raise ValueError("management_ip_filter must be a boolean")
    cidrs = policy.get("management_allow_cidrs", [])
    if not isinstance(cidrs, list) or any(not isinstance(c, str) for c in cidrs):
        raise ValueError("management_allow_cidrs must be a list of IPv4 CIDRs")
    if not ip_filter and cidrs:
        raise ValueError("Clear management_allow_cidrs when explicitly disabling IP filtering")
    if not policy.get("ingress_enabled", False):
        return  # Empty staged gateway: no public listeners, no certificate requirement yet.
    host = policy.get("management_host", "")
    if not valid_host(host) or host.endswith(".invalid"):
        raise ValueError("Configure a real, exact management hostname before enabling ingress")
    if ip_filter and (not cidrs or any(ipaddress.IPv4Network(c, strict=True).prefixlen == 0 for c in cidrs)):
        raise ValueError("IP filtering requires a source allowlist; dynamic-IP access uses management_ip_filter=false")
    for name in ("management_certificate", "management_client_ca"):
        if not CERT_ID.fullmatch(policy.get(name, "")):
            raise ValueError(f"Invalid/missing {name}")
    if inspect_files:
        from .agent import CERTS, root_file
        cert, ca = policy["management_certificate"], policy["management_client_ca"]
        for relative in (f"{cert}/fullchain.pem", f"{cert}/privkey.pem", f"{ca}/ca.pem",
                         f"{ca}/crl.pem", f"{ca}/probe.crt", f"{ca}/probe.key"):
            path = root_file(CERTS / relative)
            if relative.endswith(("privkey.pem", "probe.key")) and path.stat().st_mode & 0o077:
                raise ValueError("Management private keys must be mode 0600")


def valid_host(host):
    return (isinstance(host, str) and 1 <= len(host) <= 253
            and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                    for label in host.split('.')))


def render_frontdoor(snapshot, policy, digest, generation, admin_port):
    validate_ingress_policy(policy, inspect_files=False)
    if not policy.get("ingress_enabled", False):
        if any(route.enabled for route in snapshot.routes):
            raise ValueError("Enable the approved unified ingress before publishing business routes")
        return http_vhost(policy.get("listen_address", "127.0.0.1"), "_", True, default=True) if policy.get("acme_enabled", False) else []
    host = policy['management_host']
    cert, ca = policy['management_certificate'], policy['management_client_ca']
    address = policy.get('listen_address', '127.0.0.1')
    hosts = {host}
    for route in snapshot.routes:
        if not route.enabled:
            continue
        if (route.listen_port != 443 or route.host == host or not valid_host(route.host)
                or not route.certificate or route.auth not in ('api_key', 'mtls', 'mtls_api_key')):
            raise ValueError('Invalid remote route for unified 443 ingress')
        hosts.add(route.host)
    lines = [
        '  ssl_protocols TLSv1.2 TLSv1.3;',
        '  ssl_session_tickets off;',
        # Deny an unknown SNI at handshake, and unknown HTTP hosts on reused connections.
        f'  server {{ listen {address}:443 ssl default_server;',
        '    ssl_reject_handshake on; return 421; }',
        '  limit_req_zone $binary_remote_addr zone=sg_admin_login:1m rate=5r/m;',
        '  limit_req_zone $binary_remote_addr zone=sg_admin_api:1m rate=10r/s;',
        '  limit_conn_zone $binary_remote_addr zone=sg_admin_conn:1m;',
    ]
    lines += http_vhost(address, "_", policy.get("acme_enabled", False), default=True)
    for name in sorted(hosts):
        # Literal approved name, never an arbitrary Host header in Location.
        lines += http_vhost(address, name, policy.get("acme_enabled", False), redirect=True)
    lines += [
        f'  server {{ listen {address}:443 ssl; server_name {host};',
        f'    if ($host != {host}) {{ return 421; }}',
        f'    if ($ssl_server_name != {host}) {{ return 421; }}',
        '    if ($ssl_client_verify != SUCCESS) { return 403; }',
        f'    ssl_certificate /etc/servicegateway/certs/{cert}/fullchain.pem;',
        f'    ssl_certificate_key /etc/servicegateway/certs/{cert}/privkey.pem;',
        f'    ssl_client_certificate /etc/servicegateway/certs/{ca}/ca.pem;',
        f'    ssl_crl /etc/servicegateway/certs/{ca}/crl.pem;',
        '    ssl_verify_client on; ssl_verify_depth 2; ssl_session_cache off;',
        '    client_max_body_size 2m;',
        '    limit_conn sg_admin_conn 16; limit_conn_status 429;',
        "    add_header Strict-Transport-Security 'max-age=31536000' always;",
        # No management URLs, cookies or query strings in data-plane access logs.
        '    access_log off;',
    ]
    # mTLS, CRL, application login and throttling remain mandatory in BOTH modes.
    if policy.get('management_ip_filter', True):
        for cidr in policy['management_allow_cidrs']:
            lines.append(f'    allow {cidr};')
        lines.append('    deny all;')
    lines += [
        '    location ^~ /internal/ { return 404; }',
        '    location = /_sg/ready {',
        '      if ($remote_addr != 127.0.0.1) { return 404; }',
        f'      add_header X-SG-Generation {generation};',
        f"      return 200 '{digest}';", '    }',
    ]
    for location, rate, burst in (('= /api/auth/login', 'sg_admin_login', 5),
                                  ('/', 'sg_admin_api', 20)):
        lines += [
            f'    location {location} {{',
            f'      limit_req zone={rate} burst={burst} nodelay; limit_req_status 429;',
            f'      proxy_pass http://127.0.0.1:{admin_port};',
            '      proxy_http_version 1.1;', f'      proxy_set_header Host {host};',
            '      proxy_set_header X-Forwarded-Proto https;',
            '      proxy_set_header X-Forwarded-For $remote_addr;',
            '      proxy_set_header Forwarded "";',
            '      proxy_set_header X-SG-Secret "";',
            '      proxy_set_header X-SG-Digest "";',
            '      proxy_set_header X-SG-Route "";',
            '      proxy_set_header Connection "";',
            '      proxy_connect_timeout 3s; proxy_read_timeout 120s;',
            '      proxy_buffering off;', '    }',
        ]
    return lines + ['  }']


class LoopbackTLS(http.client.HTTPSConnection):
    """Connect to a fixed local IP, but send the actual vhost SNI (never resolve user DNS)."""
    def connect(self):
        self.sock = socket.create_connection(('127.0.0.1', self.port), self.timeout)
        self.sock = self._context.wrap_socket(self.sock, server_hostname=self.host)


def probe_ready(host, port, certificate, client_ca, digest, generation, require_sni=True):
    from .agent import CERTS
    connection = None
    try:
        if certificate:
            # Identity-only local probe; external PKI/hostname trust is separately verified at rollout.
            ctx = ssl._create_unverified_context()
            if client_ca:
                ctx.load_cert_chain(str(CERTS / client_ca / 'probe.crt'), str(CERTS / client_ca / 'probe.key'))
            connection = LoopbackTLS(host if require_sni else '127.0.0.1', port, timeout=2, context=ctx)
        else:
            connection = http.client.HTTPConnection('127.0.0.1', port, timeout=2)
        connection.request('GET', '/_sg/ready', headers={'Host': host if host != '_' else 'localhost'})
        response = connection.getresponse()
        return (response.status == 200 and response.read(100).decode() == digest
                and (not generation or response.getheader('X-SG-Generation') == generation))
    except (OSError, http.client.HTTPException, ValueError):
        return False
    finally:
        if connection:
            connection.close()


def check_frontdoor(policy, digest, generation):
    if not policy.get('ingress_enabled', False):
        return True
    host = policy['management_host']
    if not probe_ready(host, 443, policy['management_certificate'], policy['management_client_ca'], digest, generation):
        return False
    conn = http.client.HTTPConnection('127.0.0.1', 80, timeout=2)
    try:
        conn.request('HEAD', '/', headers={'Host': host})
        response = conn.getresponse()
        return response.status == 308 and response.getheader('Location') == f'https://{host}/'
    except (OSError, http.client.HTTPException):
        return False
    finally:
        conn.close()
