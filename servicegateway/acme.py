"""Only a dedicated root-owned HTTP-01 webroot is public on port 80."""
WEBROOT = '/var/lib/servicegateway/acme-webroot'


def challenge_locations(enabled):
    if not enabled:
        return []
    return [
        # A regex location prevents dotfiles and subdirectories outside the token webroot.
        '    location ~ "^/\\.well-known/acme-challenge/[A-Za-z0-9_-]{1,256}$" {',
        '      limit_except GET { deny all; }',
        f'      root {WEBROOT};',
        '      default_type text/plain;',
        '      disable_symlinks on;',
        '      try_files $uri =404;',
        '      access_log off;',
        '    }',
        '    location /.well-known/acme-challenge/ { return 404; }',
    ]


def http_vhost(address, host, enabled, redirect=False, default=False):
    lines = [f'  server {{ listen {address}:80' + (' default_server;' if default else ';'),
             f'    server_name {host};', '    client_max_body_size 1k;']
    lines += challenge_locations(enabled)
    # Server-level return would run before challenge locations and break issuance/renewal.
    lines += [f'    location / {{ return 308 https://{host}$request_uri; }}' if redirect
              else '    location / { return 404; }', '  }']
    return lines
