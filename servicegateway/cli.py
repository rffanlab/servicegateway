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
    cidrs = sub.add_parser("service-source-cidrs", help="Root-only: set one approved service's source CIDR ceiling")
    cidrs.add_argument("--service", required=True)
    cidrs.add_argument("--cidr", action="append", default=[])
    cidrs.add_argument("--inherit-global", action="store_true")
    cidrs.add_argument("--confirm-public", action="store_true", help="Required when explicitly granting 0.0.0.0/0")
    route_secret = sub.add_parser("route-secret", help="Root-only: create/export a route-origin secret for upstream authentication")
    route_secret.add_argument("--route", required=True)
    route_secret.add_argument("--output", type=Path, required=True)
    route_secret.add_argument("--rotate", action="store_true", help="Generate a new secret; it takes effect on the next route publish")
    wc = sub.add_parser("wechat-config", help="Root-only: configure one approved service's WeChat Mini Program AppID/AppSecret")
    wc.add_argument("--service", required=True)
    wc.add_argument("--appid", required=True)
    wc.add_argument("--disable", action="store_true")
    wd = sub.add_parser("wechat-disable", help="Root-only: disable WeChat login for one service")
    wd.add_argument("--service", required=True)
    export = sub.add_parser("export-e5", help="Read E5 dynamic manifests or sanitize an exported /api/overview JSON")
    export.add_argument("--overview-file")
    sub.add_parser("init-edge", help="Root-only: create the initial empty isolated Nginx config; never overwrite")
    sub.add_parser("bootstrap-ingress", help="Root-only: activate approved 80/443 entry on an empty gateway")
    from .database_cli import add_commands, run as database_command
    add_commands(sub)
    args = p.parse_args()
    if args.command.startswith("database-"):
        try:
            return database_command(args)
        except Exception as exc:
            from .business_databases import ProvisionError
            from .ipc import AgentError
            message = str(exc) if isinstance(exc, (ProvisionError, AgentError)) else type(exc).__name__
            raise SystemExit("业务数据库操作未完成：" + message) from None
    settings = Settings()
    if args.command == "register":
        from .local_registration import register_local
        try:
            register_local(args.manifest, args.approve)
        except Exception as exc:
            raise SystemExit("本机登记失败：" + type(exc).__name__ + "; 请检查 manifest、unit 授权、Agent 和数据库，未发布路由") from None
    elif args.command == "service-source-cidrs":
        if os.geteuid() != 0:
            raise SystemExit("必须由本机 root 调整服务来源授权")
        from .agent import root_file
        from .local_registration import set_source_cidrs
        host_settings = Settings(_env_file=root_file('/etc/servicegateway/app.env'))
        try:
            values = set_source_cidrs(args.service, args.cidr, host_settings, args.inherit_global, args.confirm_public)
        except Exception as exc:
            raise SystemExit("来源 CIDR 未修改：" + str(exc)) from None
        print("服务来源上限已更新；尚未发布任何路由。当前：" + (", ".join(values) if values else "继承全局策略"))
    elif args.command == "route-secret":
        if os.geteuid() != 0:
            raise SystemExit("必须由本机 root 管理上游路由 Secret")
        from .agent import root_file
        from .db import Route
        from .schemas import RouteSpec
        from .upstream_secrets import ensure, export_env, SecretError
        host_settings = Settings(_env_file=root_file('/etc/servicegateway/app.env'))
        engine, sessions = database(host_settings)
        try:
            with sessions() as db:
                row = db.get(Route, args.route)
                if not row:
                    raise SecretError("路由草稿不存在；先在后台保存路由")
                route = RouteSpec.model_validate(row.spec)
            record, changed = ensure(route, rotate=args.rotate)
            output = export_env(record, args.output)
            print(f"上游路由 Secret 已{'轮换' if changed and args.rotate else '创建/确认'}并写入 {output}（0600）；未打印 Secret。")
            print("先让上游应用接受该 Secret，再发布路由；轮换时旧线上配置在发布前仍发送旧值。")
        except Exception as exc:
            message = str(exc) if isinstance(exc, SecretError) else type(exc).__name__
            raise SystemExit("路由 Secret 操作未完成：" + message) from None
        finally:
            engine.dispose()
    elif args.command == "wechat-config":
        if os.geteuid() != 0:
            raise SystemExit("必须由本机 root 配置微信登录")
        from .agent import root_file, load_policy
        from .wechat import configure, WechatError
        host_settings = Settings(_env_file=root_file('/etc/servicegateway/app.env'))
        if args.service not in load_policy(host_settings)["services"]:
            raise SystemExit("服务尚未获得本机批准")
        try:
            result = configure(args.service, args.appid, enabled=not args.disable, ask_secret=True)
        except Exception as exc:
            raise SystemExit("微信配置未保存：" + (str(exc) if isinstance(exc, WechatError) else type(exc).__name__)) from None
        print("微信小程序登录配置已保存；AppSecret 未输出。AppID=" + str(result["appid"]))
    elif args.command == "wechat-disable":
        if os.geteuid() != 0:
            raise SystemExit("必须由本机 root 停用微信登录")
        from .wechat import disable, WechatError
        try:
            disable(args.service)
        except Exception as exc:
            raise SystemExit("微信登录未停用：" + (str(exc) if isinstance(exc, WechatError) else type(exc).__name__)) from None
        print("已停用该服务的微信登录；现有业务 Token 仍可由后台单独吊销。")
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
