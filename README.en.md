# ServiceGateway

[简体中文](README.md)

MySQL-backed, single-host service management and Nginx gateway control plane for an E5 Linux server. Includes a Chinese administrative UI, service registration, constrained lifecycle operations, upstream routing, scoped API keys, RBAC, health snapshots, audited releases and rollback.

This is a contract-compatible implementation based on the supplied E5 Business Manager registration specification, not a copy of unavailable live-server source. Existing E5 services and gateway listeners remain untouched. Complete the real-host acceptance checklist before switching traffic.

## Components

- FastAPI, SQLAlchemy 2, PyMySQL and Alembic; MySQL is mandatory in production.
- Non-root management API bound to `127.0.0.1:19092`; separate LAN console listener `19091`.
- Dedicated Nginx data-plane instance with its own config, PID, log and temporary directories; approved listeners default to `19100..19119`.
- Root broker over a group-restricted Unix socket, verified using Linux `SO_PEERCRED`. It accepts only structured operations approved by a root-owned policy and installed E5 registry manifests.
- Static local UI assets: no external CDN, front-end build dependency or fabricated dashboard data.

Routes support exact host/path matching, optional prefix removal, weighted upstreams, passive upstream failure handling, HTTP streaming, WebSocket upgrades, SSE, body limits, timeouts, IP restrictions, per-IP request limiting and locally provisioned TLS certificates.

Four auth modes: ServiceGateway session, route-scoped API key, existing E5 Manager session, or explicitly root-approved public access. Registration-scoped API keys cannot control service lifecycles. Passwords use Argon2; sessions and API keys are hashed in MySQL. Browser mutations require CSRF tokens.

## Safety and release semantics

Saving a route changes a draft only. Publishing requires the preview's revision and digest, independently validates root policy, runs `nginx -t`, atomically replaces the dedicated edge config, reloads Nginx and checks the live config fingerprint and listeners. On failure it restores the prior config. MySQL retains pending releases for crash reconciliation. Rollback selects an immutable successful gateway snapshot and does not replace the current draft or touch application data.

There is no arbitrary shell, raw Nginx editing, systemctl wildcard, writable Docker socket or business-data deletion API. Services start in forward dependency order, stop in reverse order and restart via reverse stop followed by forward start. Disabling autostart does not stop the process.

## Installation

Read [E5 deployment](docs/E5-DEPLOYMENT.md) and [acceptance](docs/ACCEPTANCE.md). From a reviewed checkout, run `sudo bash deploy/install.sh`. The first run creates an environment-file template and stops for MySQL configuration. No default admin password is supplied. Use `sgctl admin` locally to create or reset an administrator with hidden interactive password entry.

The install uses an independent schema and new ports. It must not replace the existing E5 manager, overwrite its registry, or interrupt running applications. Database schema rollback is deliberately non-destructive: restore a verified backup when necessary rather than dropping tables.

## Tests

Install `.[test]`, then run `pytest -v`. Local API tests use isolated temporary SQLite databases only; CI exercises real MySQL 8.4 migrations and API behavior. `TEST_MYSQL_URL` must point to a disposable database named `servicegateway_test`. Real Nginx tests cover HTTP/authentication, header handling, SSE streaming and WebSocket echo.

## Scope limitations

Single host and single control-plane worker; no distributed failover, cluster-wide rate limits, automatic ACME issuance, WAF, model billing or GPU scheduling. Upstreams are approved IPv4 HTTP endpoints. Certificate files are installed locally under fixed certificate IDs. Application-specific subpath/cookie/redirect compatibility must be tested. Access sampling is bounded recent-log sampling, not a historical metrics platform. Established streams are not terminated on key/session revocation. The old Manager's environment-variable editing and cleanup features are not automatically migrated.
