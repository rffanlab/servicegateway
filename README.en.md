# ServiceGateway

[简体中文](README.md) · [Remote security](docs/REMOTE-SECURITY.md)

MySQL-backed, single-host Linux service management and Nginx gateway control plane. This implements the supplied E5 registration contract, not unavailable live-server source. Existing E5 services must remain available until migration is verified.

## Components

FastAPI, SQLAlchemy, PyMySQL and Alembic; a local Chinese management UI; an independent Nginx data plane; a constrained root broker over a peer-UID-verified Unix socket. Includes service registration, health snapshots, ordered lifecycle operations, routing, scoped keys, roles, audit, draft releases and rollback.

The same managed Nginx edge owns public TCP 80 and 443. Port 80 redirects approved hosts only; 443 serves the protected management vhost and business SNI hosts. API 19092 and status 19093 remain loopback-only. There are no additional console or 191xx business listeners. Ingress is staged off until explicitly configured. See [unified ingress](docs/UNIFIED-INGRESS.md). Production requires MySQL; SQLite is allowed only in isolated tests.

## Remote security defaults

Remote mode requires a dedicated HTTPS management origin and Secure host-only cookies. The root-policy-managed admin vhost adds mTLS, CRL and source-IP restrictions, with application password authentication retained. Business hosts must differ from the management host. Remote business routes require TLS and a scoped API key or mTLS; shared admin sessions, legacy E5 auth and public routes are rejected.

The implementation includes CSRF and Host/Origin validation, bounded JSON management bodies, duplicate credential-header rejection, idle session expiry, recent-password checks for sensitive writes, credential stripping and rate/connection limits. Root-owned policy approves explicit units, endpoints and ports. The UI cannot edit that policy or run arbitrary shell/systemctl commands. Legacy E5 grants are not automatically trusted on the remote host.

Publishing checks the preview revision/digest, revalidates policy, runs nginx -t, writes a durable rollback journal, atomically replaces configuration, reloads Nginx and verifies a unique release generation. Recovery restores interrupted candidates before edge startup. Rollback does not change application data or overwrite the current draft.

## Installation and tests

Read the remote security and acceptance documents before running `sudo bash deploy/install.sh` from a reviewed checkout. The first run creates an environment template and stops. Configure a separate local MySQL database and real HTTPS origin/policy; create an administrator through interactive `sgctl admin`. There is no default password. No script changes SSH, firewall rules or cloud security groups.

Install `.[test]` and run `pytest -v`. Local API tests use temporary SQLite; CI tests MySQL 8.4 migrations and API behavior. Real Nginx tests exercise HTTP, SSE, WebSocket and certificate-authenticated TLS, including revoked-client rejection. Only a disposable database named `servicegateway_test` may be used for MySQL tests.

## Limitations

This is not a production security certification. Target-host permissions, network exposure, application isolation, backups and failure recovery need independent verification. Dependencies are not fully hash-locked yet; pin and scan the production build. No distributed management, automated DNS-01/wildcard issuance, OIDC, WAF, GPU quota or arbitrary remote SSH execution. Upstreams are approved IPv4 HTTP endpoints and require a protected network or tunnel when remote. Existing long-lived connections are not automatically disconnected upon credential revocation. Recent access sampling is not a historical metrics platform.

## Full host provisioning

`deploy/full-deploy.sh` supports Ubuntu Server 24.04/systemd. See [full deployment](docs/FULL-DEPLOYMENT.md). It installs Nginx/MySQL/Certbot, creates separate migration/runtime accounts, bootstraps HTTP-01 on the existing edge, issues production certificates after a staging dry run, creates the protected admin client identity, activates unified 80/443 and configures twice-daily renewal. It never changes SSH/firewalls/cloud security groups or replaces unknown databases/listeners.

Use `bash deploy/full-deploy.sh --dry-run` to inspect the plan. Installation requires an actual domain, email, admin source CIDR and explicit `--agree-tos`. The browser p12 and AES-GCM-encrypted CA recovery archive require a user-held passphrase. Let's Encrypt renews automatically; the private client CA's 90-day CRL is deliberately refreshed with `pki-refresh` by a passphrase holder. No plaintext CA signing key remains on disk after bootstrap. Certificate verification/renewal failures are not treated as successful deployment.
