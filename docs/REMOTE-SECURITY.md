# 远程服务器部署：安全边界与操作规范

> 统一入口部署以 [UNIFIED-INGRESS.md](UNIFIED-INGRESS.md) 为准：仅对外 80/443。本文替代旧版“局域网即可访问”的部署默认值。默认模式为 `remote`。这不是公网安全认证或零漏洞保证；完成自动化测试之后，仍必须在目标主机验收网络、身份、业务隔离和恢复。

> 完整新机安装使用 [FULL-DEPLOYMENT.md](FULL-DEPLOYMENT.md)：显式授权 HTTP-01 后，80 的独立验证路径对外可读，完成证书与身份初始化后启用 443。以下手工部署边界仍适用；无需再手工填写数据库随机凭据。

## 1. 默认拒绝暴露

不再安装独立 19091 管理入口。管理 API 仅监听 `127.0.0.1:19092`，数据面状态端口仅监听 `127.0.0.1:19093`；Agent 只提供有 Unix 用户校验的本机 socket。初始 `ingress_enabled=false` 不创建 80/443 监听，edge 只提供 loopback 状态端口；准备好证书后明确启用，由同一 edge 生成 80 跳转、443 管理台和业务虚拟主机。不开放 MySQL、Docker socket、模型服务、ComfyUI 或 Harness 内部端口。

安装器不修改 SSH、不写防火墙、不调整云安全组、不关闭旧服务、不删除业务数据。先保持第二个 SSH 会话及云厂商救援控制台可用，再由管理员审核网络规则。禁止为排障执行 `ufw reset`、清空 iptables 或临时关闭整个防火墙。

**控制台与业务必须使用不同域名，不得以“不同端口”代替身份隔离。** 管理 Cookie 不共享父域。远程模式拒绝把管理会话直接用作业务统一登录：程序调用使用路由限定 API Key，浏览器业务使用客户端证书 mTLS。未来接入 OIDC/SSO 应单独实现授权流程，不能通过扩大 Cookie Domain 临时凑合。

## 2. 已写入代码的强约束

| 项目 | 当前行为 |
|---|---|
| 远程配置 | 必须 HTTPS public origin、Secure Cookie、无 Cookie Domain；安装预检禁止测试模式、要求独立本机 MySQL 数据库 |
| 动态管理 IP | 新安装不要求固定出口 IP，mTLS + 密码强制；IP 白名单仅为可选附加条件。旧策略缺少 management_ip_filter 时保留来源限制 |
| 远程路由 | 只允许端口 443，必须精确域名、TLS、`api_key` 或 `mtls`、正数限流；不同域名可配置不同证书/客户端 CA，不允许使用管理域名 |
| 自动信任 | 不默认继承旧 E5 root 注册表；远端重新安装并经本机批准后才可管理 |
| 主机操作 | root-owned 策略、明确 unit、非 root 业务用户、拒绝 unit 别名/可写 drop-in；无任意 shell、无通配 systemctl |
| 凭据 | 密码 Argon2、会话和 API Key 哈希存储；不把 `sg_session`、`__Host-sg_session` 或网关内部密钥转发到业务 |
| 管理请求 | Host/Origin 检查、CSRF、有界 2 MiB 请求体、重复认证头拒绝、验证错误不回显输入密码 |
| 会话 | 默认 30 分钟闲置失效；敏感写操作需要最近 5 分钟内验证密码，前端有隐藏输入的重新验证窗口 |
| 业务认证 | Key 限定到具体路由或服务登记；注册 Key 无启停权限；LAN 会话路由默认仅管理员，其他用户需显式列入 session_users |
| 资源保护 | 每来源 IP 请求速率和并发连接上限、请求头/正文空闲超时；不是分布式计费或 GPU 配额系统 |
| 文件权限 | Nginx 日志目录由 root 所有，Web 用户不能写入；避免 root master 被应用可写日志路径中的符号链接引导 |
| 发布 | 草稿版本与摘要检查、root 复验、nginx -t、原子替换、reload、独立 generation 验证；同配置重新发布也会验证新 worker 已加载 |
| 中断恢复 | 修改 live 配置前落盘旧配置和 pending journal；启动 edge 前恢复未提交配置，避免重启意外激活半完成发布 |
| 鉴权版本 | 旧 worker 的配置指纹不能套用新版本较弱的认证规则；不一致时拒绝请求 |

## 3. 安装顺序

在新远程服务器独立部署，先保留 E5 作为回退源，不在第一步停用 E5 服务。已有程序/数据库/配置分别迁移，不复制整个 `/etc`、sudoers 或 root 授权表。

1. 用受限 SSH 密钥账户进入目标服务器，确认另一个可用会话和救援入口。检查现有端口、服务、磁盘和实际运行任务。
2. 克隆并审核 main 中的指定提交。先运行 `sudo bash deploy/install.sh` 生成 root-only 环境模板；配置独立 MySQL 数据库 `servicegateway` 与专用用户。
3. 设置 `SG_DEPLOYMENT_MODE=remote`、`SG_SECURE_COOKIE=true`、实际的 `SG_PUBLIC_ORIGIN=https://管理域名`。不得设置 `SG_COOKIE_DOMAIN`。
4. 重跑安装会生成 `/etc/servicegateway/policy.json`；在本机把 `management_host` 改为同一个真实域名。保持 `remote_mode=true`、`allow_public=false`、`include_legacy_registry=false`。预检不匹配时会停止，不会继续迁移数据库。
5. 再运行安装，创建管理员。新系统只在本机可访问，不会因为安装成功而暴露公网。
6. 配置管理专用域名的 HTTPS 入口，优先放在 VPN/受限网络。需要直接外部访问时，由 root policy 的 `management_*` 设置生成固定的管理虚拟主机：受信服务器证书 + 客户端证书校验 + 客户端 CA 撤销列表 + 应用密码登录，默认不限制管理出口 IP；固定来源场景可以额外开启管理 IP 白名单。
7. 示例中的管理域名和网段是占位符，不是实际配置。证书、CA、CRL、权限、域名和安全组尚未配置时，不应开放 443。不能把内部 :19092 或 :19093 直接做公网端口映射。同一 edge 必须是 80/443 的唯一所有者；安装器不强制停止冲突的系统 Nginx。
8. 每个业务在远端以专用非 root 用户安装、仅监听 loopback，验证健康地址后用 `sgctl approve` 批准真实 manifest。配置新路由并逐个验收，最后再逐项切换客户端地址。

部署命令应逐行执行；没有反斜杠续行：

```bash
git clone --branch main https://github.com/rffanlab/servicegateway.git
```

```bash
cd servicegateway && sudo bash deploy/install.sh
```

```bash
sudoedit /etc/servicegateway/app.env /etc/servicegateway/policy.json
```

```bash
sudo systemd-run --quiet --wait --pty --collect -p EnvironmentFile=/etc/servicegateway/app.env -p WorkingDirectory=/srv/e5-apps/servicegateway/current /srv/e5-apps/servicegateway/current/.venv/bin/sgctl admin rffanlab
```

这些命令不要求把 SSH/MySQL/管理员密码发到聊天或仓库。MySQL 密码写 root-only 环境文件并正确做 URL 编码，CLI 管理员密码隐藏输入。迁移账户与运行账户应分离；当前安装器需要有迁移权限的数据库凭据，迁移完毕后可由本机管理员切换为运行期 DML 账户。

## 4. 远程网页与 API 入口

API 路由使用 `auth=api_key`、真实 HTTPS 域名、本机已安装证书 ID、至少 1 的 `rate_per_second`。使用 `X-Gateway-Key`，不要把令牌放在 URL、查询参数或截图里。模型厂商的业务 Authorization 头不被网关占用。

浏览器业务使用 `auth=mtls`，必须有 `certificate` 和 `client_ca`。在浏览器/设备安装独立客户端证书。CA 签名私钥应离线保存，不能放在网关主机、代码仓库或数据库。主机只保存 CA 公钥证书、CRL，以及仅用于 loopback 发布探测的独立客户端证书/密钥。

目录结构：

```text
/etc/servicegateway/certs/<服务器证书ID>/fullchain.pem
/etc/servicegateway/certs/<服务器证书ID>/privkey.pem
/etc/servicegateway/certs/<客户端CA-ID>/ca.pem
/etc/servicegateway/certs/<客户端CA-ID>/crl.pem
/etc/servicegateway/certs/<客户端CA-ID>/probe.crt
/etc/servicegateway/certs/<客户端CA-ID>/probe.key
```

所有目录/文件 root 所有，不可被业务账户写入；私钥必须 `0600`。`probe.crt` 由该客户端 CA 签发，CA 签名密钥本身不部署。浏览器证书与 probe 证书必须不同，撤销某个浏览器证书不影响发布探测。更新 CRL/证书后重新发布并验证新 worker。TLS 会话票据和 mTLS 会话缓存关闭；已经建立的业务长连接仍不会自动踢下线，紧急撤销需管理员明确决定是否中断连接。

mTLS 解决“谁可以连接”，不替代业务自己的权限、CSRF 和文件安全。渲染危险内容、执行代码或安装插件的服务仍应使用专用用户和受控目录。网关的单次连接限额不等于底层 AI 任务数限制，应由业务队列另外约束。

## 5. MySQL、备份与升级

MySQL 只绑定 loopback 或专用受控网络；本版自动安装预检只接受本机 MySQL。远程数据库需要另行实现并验证 TLS CA/主机名认证，不能只改 URL 就通过公网连接。不要给运行账号全局权限或使用 MySQL root 运行应用。

升级前备份数据库、业务数据、现有 release 指针、root policy、证书和网关配置；加密备份异地保存，并演练恢复。发布回滚不是数据库回滚，也不是文件备份。迁移脚本不会清库；数据库损坏需要恢复经验证备份。

本版仍使用 pyproject 中的版本范围安装依赖，尚未交付完整带哈希的离线供应链构建；正式公网生产发布前需固定验收版本与依赖、执行漏洞扫描并审核构建来源。不要把 CI 通过理解成依赖没有漏洞。

## 6. 操作授权边界

账号创建、密钥创建/吊销、启停、自启修改、发布和回滚会留下审计。5 分钟敏感操作授权窗口避免每次点击都弹密码，但跨任务/长时间闲置后重新验证。生命周期超时不自动重放 restart；先查看实际进程及审计再决定后续动作。

注销只删除登记，不卸载程序，不删模型、音视频、数据库或工作区。操作前保留任务中断提示。禁止网关控制自身、SSH、MySQL、系统 Nginx；不能用 UI 关闭自己的救援入口。

当前是单主机管理：把服务部署到远程后，Agent 管理该远程主机的本地 systemd。它不是让远程网页通过任意 SSH 命令接管 E5，也不会把管理 socket 开放到网络。

## 7. 上线阻断项

以下任一未通过，保留在回环/VPN，不切换公网流量：实际 MySQL 迁移和数据恢复、域名与证书信任、无证书/错误证书/已吊销证书拒绝、错误 Host/Origin 拒绝、API Key 越权拒绝、内部端口外部不可达、Web 用户不能写 root 文件、重载失败和主机重启恢复、真实 Harness/ComfyUI 的页面和长连接、云安全组与主机防火墙从另一台外部机器检查。

自动化测试覆盖已实现代码，不替代目标服务器权限/内核/防火墙审计、第三方业务漏洞评估或独立渗透测试。

## 参考

- OWASP Session Management Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP CSRF Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- Nginx auth_request: https://nginx.org/en/docs/http/ngx_http_auth_request_module.html
- Nginx SSL / client certificates / CRL: https://nginx.org/en/docs/http/ngx_http_ssl_module.html
- systemd execution sandbox: https://www.freedesktop.org/software/systemd/man/systemd.exec.html
