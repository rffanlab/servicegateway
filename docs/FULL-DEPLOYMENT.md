# 完整部署：Nginx + MySQL + Let's Encrypt + ServiceGateway

入口：`deploy/full-deploy.sh`。适用 **Ubuntu Server 24.04 + systemd + 公开 IPv4 域名**，优先全新远程服务器。不是容器安装器，不自动升级系统，不支持用 MySQL 覆盖 MariaDB。旧的 `deploy/install.sh` 保留，作为已有依赖环境的应用升级脚本。

## 1. 你只需准备的内容

准备一个管理域名、邮箱，以及可用的 sudo/SSH。**不需要固定出口 IP**：新安装默认通过管理客户端证书 + 账号密码验证身份，换网络后无需重新登记 IP。域名 A 记录指向这台服务器；证书签发时公网 TCP 80 必须能到达网关。服务器业务流量只使用 TCP 80/443；不要开放 MySQL、19092、19093 和业务上游端口。

当前 edge 只生成 IPv4 监听，检测到 AAAA 记录会停止，不会忽略 IPv6 验证问题。通配符、只有内网解析的域名需要 DNS-01，此脚本不索取 DNS 平台 Token、不自动实现 DNS-01。使用 CDN 的域名首次安装建议 DNS-only，并确认验证路径能到达源站。

**脚本不会改 SSH、防火墙或云安全组。** 先确保有第二个 SSH 会话和云厂商救援通道，再自行审核安全组。已有程序占用 80/443 时脚本会拒绝接管，不停止或卸载它们。若预装系统 Nginx 已设置为自启，必须先审核它的现有站点和停用方案，不能与 gateway edge 同时占这两个端口。

安装会联网访问 Ubuntu 包仓库、Python 包索引和 Let's Encrypt；`--agree-tos` 表示同意 CA 条款并向 CA 提交指定域名、邮箱。DNS、云安全组和域名所有权不能由没有对应账号授权的安装脚本代替完成。

## 2. 执行

先更新项目：

```bash
git fetch origin && git switch main && git pull --ff-only origin main
```

仅预览计划（不会写文件，不执行安装命令，不要求 root）：

```bash
bash deploy/full-deploy.sh --dry-run
```

正式安装，**将下面的域名和邮箱换成真实值**：

```bash
sudo bash deploy/full-deploy.sh install --domain admin.example.com --email you@example.com --agree-tos
```

默认不传 `--admin-cidr`；不需要自动探测、追踪或记录你的出口 IP。客户端证书与账号密码、证书撤销检查、CSRF、会话过期和限流仍然生效，**不绑定 IP 不等于免登录**。

仅在有固定出口且希望叠加来源限制时，才加 `--admin-cidr 203.0.113.10/32`（示例 IP 须替换，可重复）。它是附加条件，不会取代客户端证书/密码。不要传 `0.0.0.0/0` 冒充白名单；动态出口直接省略参数。

默认管理员名 `rffanlab`，需要其他名字时加 `--admin-user`。重跑已有部署不会因为省略参数而自动移除旧白名单；旧安装的显式切换见本文第 9 节。

确实要复用已有 MySQL，先核实其只绑定本机，再显式添加 `--reuse-mysql`。脚本不会改 MySQL root 口令，不会接管同名 schema 或同名专用账号；root 通过本机 socket 认证。已有数据库需要密码时，使用仅 root 可读的 MySQL defaults 文件：

```bash
sudo bash deploy/full-deploy.sh install --domain admin.example.com --email you@example.com --agree-tos --reuse-mysql --mysql-admin-file /root/mysql-admin.cnf
```

`mysql-admin.cnf` 必须 root 所有、0600，内容是标准 `[client]` / `password=...` 格式；不要把内容提交 Git 或发到聊天。脚本不支持交互式 `mysql -p`，也不把数据库密码放在进程参数中。

PKI 初始化会隐藏输入一次口令（首次重复确认）：该口令保护浏览器 p12 和加密 CA 恢复包，至少 16 个字符。**请保存到密码管理器**，后续刷新 CRL 需要它。无人值守部署可使用 `--pki-pass-file /root/sg-pki-password`；文件同样必须 root-only 0600，部署后转移/清理这个明文口令文件，不应与恢复包长期同机保管。

## 3. 脚本执行的完整流程

| 阶段 | 操作 |
|---|---|
| 预检 | 系统/systemd、DNS A/AAAA、端口冲突、MySQL 版本及监听、已有安装归属 |
| 系统依赖 | 使用发行版 apt 安装 Nginx、MySQL、Certbot、OpenSSL、Python venv 等；已有包不做整机升级 |
| 防止抢端口 | 包安装阶段临时用 policy-rc.d 阻止自动启动；恢复原规则，禁用本次新装的系统 nginx.service，仅使用独立 edge |
| 数据库 | 新建 servicegateway schema、sg_migrate 迁移账号、sg_runtime 运行账号；生成随机凭据，保存为 root-only 文件 |
| 应用 | 安装不可变 release、执行 Alembic 迁移、启动非 root 管理 API 和受限 Agent；应用升级沿用原安装器的代码/unit 回退 |
| ACME 引导 | 先让同一个 edge 的 80 端口只提供隔离的 HTTP-01 文件验证；此时不开放登录，也不使用临时自签服务器证书对外冒充正式 HTTPS |
| 证书 | 默认先 certbot dry-run 做 staging 验证，再申请生产证书；验证域名、有效期、公钥匹配、公共信任链 |
| 管理身份 | 创建管理员随机密码、专用私有客户端 CA、浏览器 p12、探测客户端证书、CRL；CA 私钥仅保留在加密恢复包里 |
| 激活 | 配置管理域名、mTLS、密码登录与可选来源白名单；通过 root-only bootstrap 启用统一 80/443 |
| 续期 | 安装每日两次、带随机延迟的专用 systemd timer；续期成功同步文件、nginx -t、reload 并检查线上证书指纹 |
| 验收 | 本机服务状态、证书期限和发布身份检查；输出凭据/恢复包位置，外部端口和业务仍须现场验收 |

迁移账号有 schema 范围内 DDL/DML 权限；运行账号只有 SELECT/INSERT/UPDATE/DELETE。应用读取 `app.env`，迁移单独读取 `migrate.env`，不会让应用永久持有迁移账号密码。没有全局 GRANT ALL，也不使用 MySQL root 跑 Web 应用。

首次安装自动准备管理入口；不会自动迁移 E5 的实际业务、模型或业务数据库。业务接入仍遵循“本机安装、批准 manifest、登记、配置路由、预览、发布”。

## 4. 第一次登录

安装成功后，以下文件仅限 root：

```text
/root/servicegateway-access/admin-password       初始管理员随机密码
/root/servicegateway-access/admin-browser.p12    浏览器客户端证书（口令加密）
/root/servicegateway-access/client-ca.sgpki        CA 离线恢复包（Scrypt + AES-GCM 认证加密）
/etc/servicegateway/app.env                       运行数据库连接
/etc/servicegateway/migrate.env                   迁移数据库连接
/etc/servicegateway/bootstrap.json               安装归属/恢复信息，包含专用数据库凭据
```

通过受控 SSH/SFTP 把 p12 传到你自己的电脑，导入操作系统/浏览器客户端证书库（Windows 可使用“当前用户 → 个人”证书存储）。p12 口令就是安装时输入的口令。**不要把私有客户端 CA 添加为系统通用受信任网站根 CA**；网页服务器证书已经由 Let's Encrypt 签发，p12 用于向网关证明客户端身份。

打开 `https://你的管理域名/`，选择客户端证书，再用 `rffanlab` 和初始管理员密码登录。未导入证书看到拒绝访问是正常防护，不应因此取消 mTLS。不要把 p12、数据库口令、CA 恢复包放到网关 Webroot 或公开下载目录。

重跑不会重置管理员密码。需要改口令时使用原有 `sgctl admin` 交互命令，成功后妥善清理不再有效的初始密码文件。CA 签名私钥在 tmpfs 工作目录使用后删除，长期只存在于口令保护的恢复包中；恢复包必须异地备份，口令丢失不能解密恢复。

## 5. 后续新增业务证书

业务域名同样配置 A 记录，然后运行：

```bash
sudo bash deploy/full-deploy.sh certificate --domain harness.example.com --certificate-id harness --agree-tos
```

它申请/验证证书并加入自动续期清单，**不自动新建公开路由、不改任何业务权限**。随后在网关控制台填写业务域名、已批准的上游、证书 ID `harness`、API Key 或 mTLS，再发布即可。所有业务仍共用 443。

HTTP-01 的随机公开验证文件在 80 的独立目录中响应，因此新域名还没有业务路由时也能申请证书。除验证目录外，已登记域名跳转 HTTPS，未知域名返回 404。验证路径拒绝 POST、子目录、点文件和符号链接，不代理任何业务，不持有账户密钥。

业务来源白名单 `allowed_cidrs` 默认仍仅 loopback。需要远程客户端调用时，由本机管理员先审核真实允许来源；控制台每条路由的范围只能缩小、不能扩大 root 策略。管理来源白名单与业务白名单独立。

## 6. 自动续期与手工验证

Let's Encrypt 自动续期使用独立目录 `/etc/servicegateway/acme`，不会接管系统其他 Certbot 账户或证书。Nginx 使用经过验证的普通文件副本，不依赖放宽 `/etc/letsencrypt` 私钥目录权限。

```bash
sudo systemctl list-timers servicegateway-renew.timer --all
```

```bash
sudo bash deploy/full-deploy.sh renew-test
```

`renew-test` 使用 staging，不覆盖生产证书，不运行部署钩子。手工触发一次正常维护：

```bash
sudo systemctl start servicegateway-renew.service
```

```bash
sudo journalctl -u servicegateway-renew.service -n 100 --no-pager
```

续期不停止 443，不临时启动另一个 Web 服务器，不用 certbot --nginx 修改网关配置。部署钩子通过 root-only Unix socket 与发布操作串行执行。新增证书文件替换前保存 root-only 恢复记录，配置检查/重载失败时恢复旧文件；若通讯或恢复状态不确定则保留记录并拒绝继续发布，需要本机排查。Certbot 已签发但上次部署失败时，下一轮即使无需重新签发，也会重试同步。

**Let's Encrypt 服务器证书与私有客户端身份不是同一种证书。** 管理客户端 CA 不向公网 CA 申请，也不会在线存放可直接使用的 CA 签名私钥。因此管理客户端 CRL 有效期 90 天，需要持恢复包口令的人定期维护；建议每月执行：

```bash
sudo bash deploy/full-deploy.sh pki-refresh
```

该命令解密恢复包到临时目录、刷新 CRL、重新加密保存，保留同一个 CA，重载 TLS。浏览器证书接近 30 天到期时会签发替换证书并吊销旧证书，此时须重新导入输出的 p12。探测证书为长期独立身份，不能拷贝给浏览器使用。维护服务在 CRL/客户端证书临近到期时返回非零并记 journal；尚未实现邮件/短信告警，需将这个 systemd 单元接入你自己的监控。不要假设 CA 会发邮件提醒。

## 7. 重跑、升级、失败与恢复

同一参数重跑会保留已有专用数据库账号、口令、CA、管理员、服务和路由；不会强制反复申请未到期证书，不会清库。脚本对“由它完成初始化的实例”记录归属；其他方式安装的已有网关不会被自动接管，需使用 `deploy/install.sh` 升级并单独迁移证书流程。

重跑升级前，脚本把自己的 MySQL schema 和配置备份到 `/var/backups/servicegateway/`，权限仅限 root。备份包含敏感数据，尚未自动异地上传/加密/保留期清理；请纳入你现有加密备份策略，先演练恢复。不会备份所有业务数据，更不会做自动破坏性数据库 downgrade。

故障按阶段处理：DNS/ACME 失败保留本机组件和验证路径，不开放未验证的 HTTPS；应用安装失败沿用旧安装器恢复 release/unit；已安装的 apt 包和已创建的数据库不会自动卸载/删除。若中断发生在包已安装但还未写入归属状态时，再跑可能要求显式 `--reuse-mysql`，必须先核对来源，不自动猜测并接管。

包安装期间受到 SIGTERM/普通错误会恢复原 `policy-rc.d`；SIGKILL/断电无法执行 finally，下一次会检测临时标记或 `/usr/sbin/policy-rc.d.servicegateway-backup` 并停止。先核对并恢复原规则，不要盲目删除其他管理员的 policy-rc.d。

```bash
sudo bash deploy/full-deploy.sh status
```

```bash
sudo journalctl -u servicegateway.service -u servicegateway-agent.service -u servicegateway-edge.service -n 100 --no-pager
```

Certbot 详细日志在 `/srv/e5-logs/servicegateway/certbot/`。排障不要把 `.env`、bootstrap.json 或完整含凭据的 SQL 打印给机器人；脚本错误输出刻意不回显 SQL/私钥/密码输入。

## 8. 验证边界

仓库测试验证脚本输入/幂等SQL/保留数据、真实 OpenSSL 的客户端 PKI、认证加密恢复包、证书校验/恢复以及真实 Nginx HTTP-01、SSE/WebSocket、TLS/mTLS。MySQL CI 继续验证应用迁移和 API。它们不等于已经在你的远程服务器成功安装 apt 包或向 Let's Encrypt 生产 CA 实际签发证书。

上线还需实际验证：域名控制权、A/AAAA、80 入站、证书信任、客户端 p12、动态来源可用/可选白名单有效、只暴露批准的 TCP 80/443、MySQL/业务内部端口不可达、真实业务与备份恢复。脚本不是漏洞扫描器，Python 依赖尚未完整哈希锁定；需要固定生产构建并持续安装安全补丁。新脚本使用发行版包，不配置额外 PPA，不执行整机 apt upgrade。

## 9. 动态出口 IP 与旧版白名单

新安装生成 `management_ip_filter=false` 和 `management_allow_cidrs=[]`。管理虚拟主机不生成来源地址 allow/deny 规则，但仍强制 mTLS、CRL、密码登录与原有限流。运行期 MySQL、内部 API 和业务上游不会因此开放网络监听。

旧版 `policy.json` 没有 `management_ip_filter` 字段时，按 `true` 处理，保留原白名单；升级或省略 `--admin-cidr` 重跑不会静默放宽旧访问权限。首次部署尚未执行的用户直接使用第 2 节不带 IP 的命令即可。

已经启用旧白名单时，先保留私有 SSH/救援通道并备份 `/etc/servicegateway/policy.json`；升级应用后，由本机管理员只改以下管理字段，其他键原样保留：

```json
{
  "management_ip_filter": false,
  "management_allow_cidrs": []
}
```

随后从现有可用的管理入口走“预览 → 发布”应用新策略；仅编辑 JSON 或执行 Nginx reload 不会重新生成配置。不要清空现有业务路由来重新 bootstrap。如果已因旧来源限制无法访问管理入口，先通过私有救援恢复受控管理访问，再执行正常发布，不关闭 mTLS 或密码登录。新策略发布失败时沿用已有网关配置恢复流程，核对线上结果后再移除旧策略备份。

业务 `allowed_cidrs` 与管理 IP 策略独立，不随此次更新放宽。业务客户端也使用动态 IP 时，可以由本机管理员**明确审核**业务根策略 `allowed_cidrs=["0.0.0.0/0"]`，再对选定路由发布；远程模式仍强制 TLS + 路由 Key 或 mTLS，禁止 public 路由。不要据此向公网开放业务上游/MySQL 端口。云安全组或主机防火墙若仍把 TCP 443 限定为旧出口 IP，也需独立审核调整；脚本不会自动修改它们。

## 官方依据

- Certbot webroot、dry-run、部署钩子、自动续期：https://eff-certbot.readthedocs.io/en/stable/using.html
- Let's Encrypt HTTP-01 与端口要求：https://letsencrypt.org/docs/challenge-types/
- Let's Encrypt IPv6 验证：https://letsencrypt.org/docs/ipv6-support/
- Ubuntu Nginx 安装：https://documentation.ubuntu.com/server/how-to/web-services/install-nginx/
