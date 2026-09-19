"""Local administration. Credentials never appear in command-line arguments."""
import argparse
import getpass
import json
import os
from pathlib import Path
from sqlalchemy import delete, select
from .config import Settings
from .db import Audit, LoginSession, User, database
from .schemas import ServiceSpec, Snapshot, endpoint
from .security import ph


def main():
    p = argparse.ArgumentParser(prog="sgctl")
    sub = p.add_subparsers(dest="command", required=True)
    reg = sub.add_parser("register", help="Register a local business manifest; does not publish or start services")
    reg.add_argument("manifest")
    reg.add_argument("--approve", action="store_true", help="Explicitly approve installed loopback units first (root only)")
    a = sub.add_parser("admin", help="Create/reset administrator using hidden interactive password")
    a.add_argument("username")
    approve = sub.add_parser("approve", help="Root-only: approve an already installed service manifest")
    approve.add_argument("manifest")
    export = sub.add_parser("export-e5", help="Read E5 dynamic manifests or sanitize an exported /api/overview JSON")
    export.add_argument("--overview-file")
    sub.add_parser("init-edge", help="Root-only: create the initial empty isolated Nginx config; never overwrite")
    sub.add_parser("bootstrap-ingress", help="Root-only: activate approved 80/443 entry on an empty gateway")
    args = p.parse_args()
    settings = Settings()
    if args.command == "register":
        from .local_registration import register_local
        try:
            register_local(args.manifest, args.approve)
        except Exception as exc:
            raise SystemExit("本机登记失败：" + type(exc).__name__ + "; 请检查 manifest、unit 授权、Agent 和数据库，未发布路由") from None
    elif args.command == "bootstrap-ingress":
        if os.geteuid() != 0:
            raise SystemExit("Ingress bootstrap requires local root")
        from .ipc import AgentClient
        result = AgentClient(settings.agent_socket).call("bootstrap-ingress")
        print(json.dumps(result))
        print("已验证 80/443 入口；未修改 SSH、防火墙或业务数据。")
    elif args.command == "admin":
        from .main import LoginBody
        LoginBody(username=args.username, password="validation-only")
        password = getpass.getpass("管理员密码（至少 12 位）: ")
        if len(password) < 12 or len(password) > 256 or password != getpass.getpass("再次输入: "):
            raise SystemExit("密码太短、太长或两次输入不一致；未修改")
        engine, sessions = database(settings)
        with sessions.begin() as db:
            user = db.scalar(select(User).where(User.username == args.username.lower()))
            if user:
                user.password_hash, user.role, user.enabled = ph.hash(password), "admin", True
                db.execute(delete(LoginSession).where(LoginSession.user_id == user.id))
            else:
                db.add(User(username=args.username.lower(), password_hash=ph.hash(password), role="admin"))
            db.add(Audit(actor="local-cli", action="admin.reset", target=args.username.lower(), outcome="success", detail="All prior sessions revoked"))
        engine.dispose()
        print("管理员已保存；未输出口令。")
    elif args.command == "approve":
        if os.geteuid() != 0:
            raise SystemExit("必须由本机 root 执行批准；Web API 无此权限")
        from .local_registration import approve as approve_spec, read_manifest
        spec = read_manifest(args.manifest)
        approve_spec(spec, settings)
        print(f"已批准 {spec.id}；可用 sgctl register 登记，不会启动业务。")
    elif args.command == "export-e5":
        from .agent import load_policy
        if args.overview_file:
            data = json.loads(Path(args.overview_file).read_text())
            candidates = data.get("assets", [])
        else:
            candidates = load_policy(settings)["legacy_manifests"]
        output = []
        for row in candidates:
            clean = {key: value for key, value in row.items() if key in ServiceSpec.model_fields}
            if "services" not in clean and row.get("units"):
                clean["services"] = [x if isinstance(x, str) else x.get("unit", x.get("name")) for x in row["units"]]
            # Never invent missing health URLs or execute/evaluate the old app.py.
            try:
                output.append(ServiceSpec.model_validate(clean).model_dump())
            except ValueError:
                import sys
                print(f"跳过不完整资产 {row.get('id', '?')}：请补齐实际 health_url/端口/unit。", file=sys.stderr)
        print(json.dumps(output, ensure_ascii=False, indent=2))
    elif args.command == "init-edge":
        if os.geteuid() != 0:
            raise SystemExit("Root required")
        from .agent import CONFIG, atomic_write, load_policy
        from .ingress import validate_ingress_policy
        from .nginx import render
        if CONFIG.exists():
            print("保留已有网关配置，未覆盖。")
            return
        snap = Snapshot()
        policy = load_policy(settings)
        validate_ingress_policy(policy, inspect_files=True)
        atomic_write(CONFIG, render(snap, policy, snap.digest(), settings.auth_secret(), settings.admin_port))
        print("已创建空网关配置；未修改系统 Nginx。")


if __name__ == "__main__":
    main()
