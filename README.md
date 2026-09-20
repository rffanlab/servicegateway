# ServiceGateway

**MySQL 驱动的 Linux 服务管理与网关控制台。默认面向远程服务器，安装后不自动开放公网。**

[完整一键部署](docs/FULL-DEPLOYMENT.md) · [English](README.en.md) · [统一 80/443 入口](docs/UNIFIED-INGRESS.md) · [远程部署安全规范](docs/REMOTE-SECURITY.md) · [E5 资产迁移](docs/E5-DEPLOYMENT.md) · [架构](docs/ARCHITECTURE.md) · [验收清单](docs/ACCEPTANCE.md)

当前为单主机功能版 0.1.0。合并代码不代表已经执行生产部署。依据已有 E5 Business Manager 注册合同实现兼容能力，不宣称复制了未提供的 E5 线上源码。代码测试通过不等于目标服务器已部署或通过安全审计。

## 功能

| 模块 | 已实现 |
|---|---|
| 中文控制台 | 登录、服务状态、路由表单、发布与回滚、密钥、用户权限、审计、访问采样 |
| 服务管理 | 原 manifest 字段兼容、幂等登记、导入预览、HTTP 健康、systemd 状态、启停/重启/自启、仅注销登记 |
| 网关 | 独立 Nginx 实例；端口/精确域名/路径路由、前缀移除、加权多上游、最少连接、IP 绑定 |
| 协议 | HTTP、TLS、SSE、WebSocket、流式上传下载；业务流量不经过 Python 转发 |
| 身份与防护 | Argon2、哈希会话与 API Key、角色权限、CSRF、Host/Origin、闲置失效、敏感操作重验、IP/速率/连接限制 |
| 发布 | 草稿版本与摘要检查、白名单复验、nginx -t、原子写入、独立发布 generation、落盘中断恢复、历史快照回滚 |
| 运维 | MySQL + Alembic；非 root 控制台、受限本机 Agent、安装/回退脚本、日志轮转、CLI、CI 与测试 |

## 默认安全边界

**对外仅 TCP 80/443，由 ServiceGateway 的同一个 Nginx edge 实例统一管理。80 只跳转已登记域名到 HTTPS，443 按 SNI/域名分别转发管理台和业务。** 管理 API `127.0.0.1:19092`、状态端口 `127.0.0.1:19093` 不对外开放。不再创建 19091 控制台入口或 191xx 业务入口。初始 `ingress_enabled=false`，不会在证书与认证策略准备前开监听。Agent 只有带对端 Unix 用户校验的本机 socket，没有网络监听和任意 shell。

远程模式必须使用专用 HTTPS 管理域名及 Secure host-only Cookie。受 root 策略保护的管理虚拟主机提供 mTLS、CRL 与应用密码登录，默认不绑定管理电脑的出口 IP；固定来源场景可额外启用 IP 白名单。业务域名必须与管理域名隔离；远程路由只允许 **HTTPS + 限定 API Key** 或 **mTLS 客户端证书**。旧 E5 会话、共享会话路由和 public 模式仅供显式 LAN 策略使用，不是远程默认值。

Web 用户不能写 root policy、systemd unit、sudoers 或 Nginx 日志目录。服务在目标主机安装并经本机管理员批准后才能登记/控制；不自动继承旧 E5 主机授权。不允许控制网关自身、SSH、MySQL 或系统 Nginx。

## 完整部署（含 Nginx / MySQL / Let's Encrypt）

Ubuntu Server 24.04 新服务器使用 `deploy/full-deploy.sh`；原 `deploy/install.sh` 继续用于仅应用升级。先设置管理域名 A 记录、放行 HTTP-01 所需 TCP 80，并保留 SSH 救援。以下域名、邮箱都是需要替换的示例：

```bash
sudo bash deploy/full-deploy.sh install --domain admin.example.com --email you@example.com --agree-tos
```

脚本安装依赖、创建 MySQL schema/独立迁移与运行账号、申请管理服务器证书、生成管理客户端 p12/加密 CA 恢复包、初始化管理员并启用统一 80/443。Let's Encrypt 每日两次自动检查续期；管理客户端 CRL 使用独立每日任务检查，不足 30 天自动刷新至 90 天；旧安装执行一次 `pki-auto-enable` 授权主机加密凭据。现有端口/未知数据库冲突会拒绝覆盖；不修改 SSH、防火墙或云安全组。先用 `bash deploy/full-deploy.sh --dry-run` 查看计划，细节和首次登录见[完整部署说明](docs/FULL-DEPLOYMENT.md)。

## 开始部署

先阅读 [统一入口部署](docs/UNIFIED-INGRESS.md) 和 [远程安全规范](docs/REMOTE-SECURITY.md)。在远程机独立部署，不先停用 E5。

```bash
git clone --branch main https://github.com/rffanlab/servicegateway.git
```

```bash
cd servicegateway && sudo bash deploy/install.sh
```

首次生成 root-only 环境模板并停止，随后配置独立本机 MySQL `servicegateway` 数据库、实际 HTTPS 管理域名和匹配的 root policy。没有默认管理员口令；CLI 交互创建管理员，不把密码放命令参数。安装器不修改 SSH、防火墙或云安全组，不迁移/删除业务数据。

**安装成功不代表对外可用。** 证书、受限外部入口、业务审批和外部网络验收必须按部署规范完成；不要为了临时访问关闭 Secure Cookie 或把所有端口开放。

## 后台与本机运维

“账户与证书”支持所有用户修改自己的密码（成功后全部会话退出），管理员可校验当前密码后下载加密客户端 P12。服务新增是逐字段表单，支持多 unit 和已批准服务预填；本机部署可用 `sgctl register <manifest> --approve` 一次批准并登记，普通业务可用 `deploy/register-local.py` 加限定 Key 提交。

Agent socket 固定 root:servicegateway 0750/0660，部署后以普通 Web 用户实际读取访问采样。CRL 自动维护不自动更换浏览器证书；它使用主机可解密的 root-only 凭据，不等于离线 CA。升级、一次授权、下载边界和本机登记示例见 [运维升级说明](docs/OPERATIONS-UPGRADE.md)。

## API 与状态

管理写操作需要会话和 CSRF；敏感操作超过 5 分钟重新验证密码。operator 可启停服务，admin 管理配置与用户。限定服务登记 Key 只能登记指定服务，不能控制启停。登录后 `/api/schema` 提供 OpenAPI JSON。

`POST /api/registry/services` 登记服务；`PUT /api/routes/{id}?revision=N` 只保存草稿；`POST /api/gateway/preview` 后携相同 revision/digest 调用 `/api/gateway/publish`；`/api/gateway/rollback/{id}` 恢复成功快照，不覆盖编辑草稿或业务数据；`/api/gateway/reconcile` 核对未决发布，不盲目重试。

## 测试

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
```

```bash
.venv/bin/pytest -v
```

本地 API 测试使用临时 SQLite；生产拒绝 SQLite。CI 使用专用 MySQL 8.4 数据库验证迁移及 API，真实 Nginx 验证 HTTP、凭据剥离、SSE、WebSocket 与 TLS/mTLS/CRL。`TEST_MYSQL_URL` 只允许数据库名 `servicegateway_test`，不允许使用业务数据库。

## 边界

单主机、单控制面 worker；不包含分布式高可用、DNS-01 通配符签发、OIDC、WAF、模型计费、GPU 任务配额、远程 SSH 命令执行或旧环境变量管理的自动迁移。上游只接受批准的 IPv4 HTTP 地址；远端上游需走受控专网/加密隧道，不应通过公网明文转发。

访问采样不是全量时序监控。撤销 Key/证书或退出登录不会强制断开已建立的长连接。路径代理不自动修复应用的绝对 URL、Cookie Path 和重定向。依赖尚未完整哈希锁定，公网生产前需要固定版本、漏洞扫描、备份恢复和真实主机验收。

## 业务数据库创建

管理员可在“业务数据库”表单或服务卡片创建新业务库，本机部署可使用 `sgctl database-create`。通过 `sgctl database-enable` 一次性启用受限本机执行器；不授予 Web 运行账号全局 MySQL 权限。每个已批准服务对应独立 `sgb_` 库及运行/迁移账号，支持验证密码后下载连接配置、同名拒绝接管、幂等及中断保留；不包含删库或任意 SQL 接口。升级和账号权限说明见 [业务数据库](docs/BUSINESS-DATABASES.md)。
