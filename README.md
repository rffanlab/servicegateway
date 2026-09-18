# ServiceGateway

**面向 E5 Linux 主机的服务管理与网关控制台，生产数据库使用 MySQL。**

[English](README.en.md) · [E5 部署与迁移](docs/E5-DEPLOYMENT.md) · [架构与边界](docs/ARCHITECTURE.md) · [上线验收](docs/ACCEPTANCE.md)

这是一个独立的网关管理服务，不是只展示端口链接的导航页。它维护服务登记、网关路由草稿、认证、发布快照、健康状态和审计，并通过单独的 Nginx 实例承载实际业务流量。

> 当前版本：0.1.0，单主机功能版。依据已有 E5 Business Manager 接入合同重建兼容能力，不宣称复制了 E5 上未提供的全部源码。上线前必须完成真实 E5 验收；不要直接替换现有 Manager 或业务入口。

## 已实现

| 模块 | 功能 |
|---|---|
| 中文管理控制台 | 登录、真实运行总览、服务管理、路由表单、发布/回滚、API Key、用户角色、操作审计、访问采样 |
| 服务管理 | 兼容原服务 manifest；动态登记、幂等更新、导入预览、HTTP 健康检查、systemd 进程状态、启停/重启/自启、仅注销登记 |
| 网关路由 | 独立端口、精确域名、路径前缀、可选去前缀、多上游权重、轮询/最少连接/IP 绑定、请求大小与空闲超时 |
| 协议 | HTTP、WebSocket、SSE、流式上传/下载；不在 Python 中转发业务内容 |
| 安全 | Argon2 密码、HttpOnly 会话、CSRF、三种用户角色、哈希存储的限定作用域 API Key、全局/路由 IP 白名单、每来源 IP 限流 |
| 统一认证 | 新控制台会话、API Key、旧 E5 登录态、显式公开路由（默认禁止）四种模式 |
| 发布 | 草稿版本检查、配置预览、结构化白名单复验、nginx -t、原子文件替换、reload、配置指纹与监听检查、失败恢复、历史快照回滚、未决状态核对 |
| 持久化 | MySQL + SQLAlchemy + Alembic；配置、会话、API Key 哈希、发布、健康快照和审计均入库 |
| 本机代理 | Unix socket + SO_PEERCRED，root-owned 策略；只操作已批准的明确 unit 与上游，不提供 shell、通配 systemctl 或任意 Nginx 配置 |
| 运维交付 | 独立 systemd 服务、安装/回退脚本、MySQL 建库模板、日志轮转、CLI 管理员恢复、测试与 CI |

## 部署结构

```text
浏览器 / API 客户端
  ├─ 管理入口 :19091 → 127.0.0.1:19092 FastAPI 控制台 → MySQL
  └─ 业务入口 :19100…19119 → 独立 Nginx edge → 已批准的业务上游
                              │ auth_request
                              ├─ ServiceGateway /internal/auth
                              └─ 旧 E5 Manager :18090 /api/auth/me（e5 模式）

非 root 控制台 ── Unix socket ── 本机受限 root Agent ── 白名单 systemd / 独立 edge 配置
```

控制台使用单 worker，发布代理使用本机互斥锁。Nginx 数据面与控制面分进程：控制台重启不重启业务应用，但依赖控制台鉴权的新请求在控制台不可用时会拒绝访问，而不是绕过认证。

## 在 E5 上开始

先阅读 [部署文档](docs/E5-DEPLOYMENT.md)。下面命令均为单行，可以逐条复制；不要把占位密码直接投入使用。

```bash
git clone --branch feat/e5-mysql-gateway https://github.com/rffanlab/servicegateway.git
```

```bash
cd servicegateway && sudo bash deploy/install.sh
```

首次执行只会生成 `/etc/servicegateway/app.env` 并提示配置数据库；**没有默认管理员口令**。配置独立 MySQL 数据库与账号后重跑安装，再用 CLI 交互创建管理员。部署脚本不安装/升级你的业务程序，不删除原 Manager、旧 Nginx 站点、模型或业务数据。

默认仅允许 `127.0.0.1` 和 `192.168.1.0/24` 访问新控制台；与实际网段不符时，应先在本机审核调整。默认业务端口是新端口范围；真实主机必须先确认无端口冲突。

## 开发与测试

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
```

```bash
.venv/bin/pytest -v
```

默认 API 测试仅在临时 SQLite 文件执行，以便无数据库的开发机器快速测试；生产配置明确拒绝 SQLite。CI 另用真正的 MySQL 8.4 验证 Alembic 和同一套 API 测试，真实 Nginx 进程验证 HTTP/鉴权、请求透传、SSE 与 WebSocket。测试数据库名限定为 `servicegateway_test`，不允许使用业务数据库。

## API 要点

所有管理写操作需要管理员会话和 `X-CSRF-Token`；operator 可执行服务生命周期操作。浏览器登录后可在 `/api/schema` 查看完整 OpenAPI JSON。

- `POST /api/registry/services`：原 manifest 形状，新增登记必须已有本机批准。可使用限定 `service_ids` 的 `X-Gateway-Key`，但这类 Key 不能启停服务。
- `PUT /api/routes/{id}?revision=N`：保存路由草稿；不会直接改变线上流量。
- `POST /api/gateway/preview` → `POST /api/gateway/publish`：预览后携带相同 `revision`、`digest` 发布。
- `POST /api/gateway/rollback/{release_id}`：恢复成功历史网关快照，不覆盖编辑草稿或业务数据库。
- `POST /api/gateway/reconcile`：核对崩溃/超时后的未决发布；不盲目重复发布。

旧 Manager 的 `X-E5-Confirm` 本机免登录例外**不在新 API 中默认开启**；请迁移为管理员会话或限定注册 Key。既有 E5 网关仍可继续使用旧登录态，迁移期无需停用旧平台。

## 当前明确不包含

多主机 Agent 编排、分布式高可用、自动 ACME 签发续期、WAF、OpenAI 模型计费/配额、GPU 任务排队、任意 Docker socket 控制、业务部署脚本在线编辑、旧 Manager 环境变量管理/日志清理的自动迁移。TLS 使用本机管理员安装的固定证书目录；HTTP 上游目前仅接受批准的 IPv4 字面量地址。

访问采样只显示最近完成请求，不是完整时序监控；长连接结束后才记访问日志。API Key 撤销和退出登录不会强制断开已经建立的 WebSocket/SSE。路径代理不能自动修复所有应用的绝对路径、Cookie Path 或重定向；不支持子路径的服务应优先使用独立端口或域名。
