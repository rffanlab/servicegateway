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
    if args.command == "bootstrap-ingress":
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
        from .agent import atomic_write, root_file, unit_info
        spec = ServiceSpec.model_validate_json(Path(args.manifest).read_text())
        for unit in spec.services:
            unit_info(unit)
        address, port = endpoint(spec.health_url)
        if address != "127.0.0.1":
            raise SystemExit("自动批准仅接受 loopback 健康目标；远端上游须本机审核 policy.json")
        policy_path = root_file(settings.policy_file)
        policy = json.loads(policy_path.read_text())
        grant = {"units": spec.services, "upstreams": [f"{address}:{port}"], "health_url": spec.health_url}
        if spec.id in policy.get("services", {}) and policy["services"][spec.id] != grant:
            raise SystemExit("已有不同授权；拒绝静默覆盖，请本机审核")
        policy.setdefault("services", {})[spec.id] = grant
        atomic_write(policy_path, json.dumps(policy, ensure_ascii=False, indent=2) + "\n", 0o640)
        print(f"已批准 {spec.id}；未安装、启动、注册或发布任何业务。")
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
