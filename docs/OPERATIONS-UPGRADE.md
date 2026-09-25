# 自动 CRL、账户操作、访问采样与本机业务登记

本轮在已有 MySQL / 80、443 单入口架构上补齐运维功能，不增加公网端口，不绑定管理员出口 IP。此文覆盖早期文档中“CRL 必须每月手工刷新”和“服务只能填 JSON”的旧流程。

## 1. 已有服务器更新

在仓库目录执行（每条均为单行）：

```bash
git fetch origin && git switch main && git pull --ff-only origin main
```

已安装 Nginx/MySQL 的机器只升级应用，不必重新申请证书或重置数据库：

```bash
sudo bash deploy/install.sh
```

升级会重启管理 API 和 Agent，通常不重启已有 edge。它保留数据库、账户、客户端身份和业务配置；浏览器正在执行的管理请求可能短暂中断。升级前保留可用 SSH/私有救援通道和已验证备份。

本次修复 Agent 运行目录：systemd 单元声明 `User=root`、`Group=servicegateway`、`RuntimeDirectoryMode=0750`，不再试图用 ExecStartPre 的 chgrp 临时修改归属。socket 保持 `root:servicegateway 0660`，并继续校验对端 UID；不会使用 0777。安装器在 API 启动后以真实 Web 用户连接 Agent，读取状态和访问采样，而不是只用 root 或 /readyz 验收。

## 2. 管理客户端 CRL 自动刷新

新完整安装默认启用。已有安装只需在服务器执行一次，并隐藏输入原 PKI/P12 保护口令：

```bash
sudo bash deploy/full-deploy.sh pki-auto-enable
```

随后可立即运行一次检查并查看定时器：

```bash
sudo systemctl start servicegateway-pki-refresh.service && sudo systemctl list-timers servicegateway-pki-refresh.timer --all
```

定时器每天检查，随机延迟不超过一小时，支持关机期间错过任务后的补跑。CRL 剩余超过 30 天不重复签发；不足或等于 30 天则刷新为 90 天。刷新保留原 CA、全部已有吊销记录和现有浏览器证书，不自动替换、吊销管理员正在使用的证书。

**CRL 刷新与浏览器证书续期不是一回事。** 原浏览器证书仍有自己的有效期；接近到期时有计划地执行 `pki-refresh`、下载新 P12 并重新导入，不能等待 CRL 定时器替换证书。本轮也不扩展为所有业务自建 CA 的自动管理。

任务会解密现有恢复包到私有临时目录、签发 CRL、验证 CA 和签名并拒绝丢失原吊销记录的 CRL。只有本机 UID 0 能向 Agent 提交 CRL。Agent 与路由发布串行操作；替换前落盘备份，执行 nginx -t、reload，并用本次 CRL 专属标识确认新配置已加载。失败恢复旧文件；状态不明则保留 journal 阻止继续发布。任务不会因为报错就关闭客户端认证。

维护记录在 `/etc/servicegateway/pki-auto/status.json`，后台“账户与证书”显示定时器状态、CRL 剩余天数、最后执行结果。完整日志：

```bash
sudo journalctl -u servicegateway-pki-refresh.service -n 80 --no-pager
```

### 自动化的安全取舍

无需人工口令的任务必须拥有可用的签名凭据，无法同时声称“完全离线 CA”和“本机无人值守签名”。本版不把口令写入命令行、环境变量、MySQL 或 Web 配置；使用 `systemd-creds --with-key=host` 加密保存在 `/etc/servicegateway/pki-auto/passphrase.cred`（root-only），由任务的 `LoadCredentialEncrypted` 在启动时提供。

**这属于主机保护的在线维护权限，不抵御服务器 root 已被攻陷。** Web 进程不读取这个凭据、不访问恢复包，也不获得签名接口。保留异地加密恢复包和密码管理器里的原口令；主机加密凭据不可当成可移植备份。停用自动刷新可以执行 `sudo systemctl disable --now servicegateway-pki-refresh.timer`，之后必须自行维护 CRL 到期时间。

## 3. 登录后下载客户端证书

后台新增“账户与证书”。管理员点击“下载客户端证书”，再次输入**当前网站登录密码**后下载加密的 `admin-browser.p12`。导入 P12 时依旧使用原 **PKI/P12 保护口令**，不是网站登录密码；两者不能混淆。

下载仅限 admin 角色，使用带 CSRF 的 POST、会话与密码校验，返回 `no-store` 二进制附件并记审计。不公开下载 URL，不把文件放进 static/webroot，不导出 CA 签名私钥、CA 恢复包或 probe 私钥。Web 进程不能浏览 /root；本机初始化/升级只将加密 P12 复制到 root-only 的固定暂存路径，Agent 按固定动作返回该文件。

这里下载的是现有**管理设备证书包**，不是给任意普通账户签发独立证书。因此 viewer/operator 只能修改自己的密码，不能下载管理员 P12。

**初次登录仍受 mTLS 保护。** 首台设备保留原 SSH/SFTP 取得并导入 P12 的引导流程；已登录设备可以在后台重新下载以便受控转移到新设备。没有增加“尚未登录即可下载私钥”的入口，也没有把 mTLS 改成可选。

## 4. 用户自行修改密码

所有启用账户均能在“账户与证书 → 修改密码”填写当前密码、新密码和确认密码。新密码 12–256 位，必须与旧密码不同；校验 CSRF、当前口令和两次输入，失败不修改密码。

成功后立即使该账户**所有会话（包括当前设备）失效**，强制用新密码登录；并发登录与改密通过数据库行锁协调。API Key、证书和其他账户不因改密改变。审计不记录密码。初始 `/root/servicegateway-access/admin-password` 文件不会自动更新，改密后应由本机管理员妥善清理旧密码备份，不能拿旧初始密码文件作为当前凭据。

## 5. 表单新增服务

“服务管理 → 新增服务”默认使用表单：服务 ID、显示名称、说明、访问 URL、展示入口端口、健康地址、资源说明、风险提示，以及可增减的 systemd unit 行。多 unit 保持填写顺序，先启动的放前面。

也可以从下拉框选择“已批准服务”自动填入真实 ID、unit 和健康地址。编辑禁止更改 ID；服务登记仍然不安装业务、不启停进程、不创建公网路由。需要原始批量清单时仍保留 E5 导入入口。

网页账户不能填写一个陌生 unit 就自动取得系统权限。首次批准与实际程序安装在本机完成；下面的本机命令可把批准与登记合并成一次显式操作。

## 6. 本机业务提交

### 本机管理员或部署 Agent

参考 `examples/service-registration.json`，把示例改为本机真实 unit/健康地址后执行：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl register /实际路径/service-registration.json --approve
```

`--approve` 表示显式批准已经安装、以非 root 用户运行的本机业务，并登记到 MySQL；不会安装、执行任意命令或发布路由。冲突授权拒绝覆盖。已经批准的服务可以省略 `--approve`。重复提交相同内容返回 `changed=false`，不会重复增加版本。

### 普通业务进程自行提交

先由管理员批准 manifest，并在后台创建只有相应 **service_ids** 的“登记作用域”API Key。把 Key 保存为业务用户自己所有、权限 0600 的文件，不放在命令行、日志或仓库。业务端无需 FastAPI/SQLAlchemy 依赖，使用标准库脚本：

```bash
python3 deploy/register-local.py --manifest /实际路径/service-registration.json --key-file /安全目录/registration.key
```

脚本固定访问 `127.0.0.1:19092/internal/registry/services`，不使用代理、不跟随重定向；服务端要求实际对端是 loopback，且 Key 未过期/未撤销、范围包含提交 ID、unit/健康地址已经获 root 批准。管理员 Cookie、伪造 X-Forwarded-For、只含路由访问权限的 Key 都不能替代登记凭据。公网 Nginx 不转发 `/internal/`。

本机登记不等于允许外部访问。登记完成后，仍在后台配置并发布 443 路由；MySQL、19092、19093 和业务原始端口保持内部使用。

## 7. 验收范围

自动测试覆盖：改密后全部会话失效与旧密码拒绝、角色/CSRF/下载边界、加密 P12、CRL 续期与吊销记录保留、客户端证书不被自动轮换、失败恢复、限定本机 Key 注册、表单转换、真实 Nginx 及 MySQL 回归。Ubuntu CI 另运行真实 systemd socket 对照和加密凭据加载测试。

不能把测试通过当成现场升级完成。目标机应核实实际采样、证书下载/导入、任务日志、改密重新登录，以及真实业务登记和网关转发。云安全组、SSH、域名和当前任务未由这些代码提交自动修改。

## 官方参考

- systemd 执行环境及凭据：https://www.freedesktop.org/software/systemd/man/systemd.exec.html
- systemd-creds：https://www.freedesktop.org/software/systemd/man/systemd-creds.html
- OpenSSL CRL 签发：https://docs.openssl.org/3.0/man1/openssl-ca/
- OWASP 账户认证与改密：https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html


## 8. 最近路由与业务身份更新

### 管理前端升级后仍显示旧选项

管理页 `/`、`/login` 和 `/static/*` 现在统一返回 `Cache-Control: no-store, max-age=0`。升级切换 release 后重新打开或刷新后台即可加载当前 `app.js`，不再依赖硬刷新。若现场仍看不到“业务自行鉴权 / 公开透传”，先核对目标机 `git rev-parse HEAD` 与 `/srv/e5-apps/servicegateway/current` 是否已切到最新 release，再检查返回的 `/static/app.js`。

### 路由复制

复制路由会复用普通配置，但不复用每路由 Secret。新副本默认 `upstream_auth=none`。如果新 route 需要 route secret，再显式启用并执行：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl route-secret --route 实际路由ID --output /root/实际路由ID-gateway.env
```

发布预览若发现缺 Secret 会直接阻止发布。已经在旧版本中保存、仍带 `route_secret` 的副本不会被升级脚本擅自改写；需要在后台把“上游身份确认”改为 `none`，或者按上面的命令为该 route 单独配置 Secret。

### 鉴权切换

mTLS 路由复制或编辑后切换到 API Key、微信用户或业务透传时，后台会自动清空旧 `client_ca`。后端不会静默容忍残留字段，直接 API 提交“非 mTLS + client_ca”仍返回校验错误。

### 路由层级

同一 host 可以配置不同层级：

```text
/api/           -> service_auth
/api/private/   -> wechat_user
/api/admin/     -> mtls_or_api_key
```

权限始终按最具体下级路径执行。无尾斜杠边界（例如 `/api/private`）也会内部归一到下级路径后重新执行下级鉴权，不能回落到公开父路由。

### 微信业务用户

业务用户、微信身份、业务 Session 与网关管理员账号分离。AppSecret 只由 root Agent 使用；业务后端优先消费可信 `X-SG-User-*` / OpenID 头，需要主动解析 Token 时使用 loopback introspection，并携带具有对应 `user_service_ids` 作用域的专用 Key。


### API Key 可见与复制

新版本不再采用“密钥只显示一次”。管理员进入“API 密钥”页面后可以查看完整 Key 并一键复制。运行时鉴权仍通过 SHA-256 哈希匹配；为了支持后续显示，新创建的 Key 会额外保存 AES-GCM 加密副本。

升级前已经存在的 Key 只有不可逆哈希，没有任何方式恢复原始明文。它们会继续正常鉴权，但后台显示“旧密钥不可恢复，请重建”。重新创建同等作用域的新 Key、替换业务侧配置并撤销旧 Key 后，新的 Key 就可长期在后台复制。

加密副本依赖当前主机 `auth-secret`。正常升级不会更换该文件；如果人为更换 `auth-secret`，既有 Key 的哈希鉴权仍可继续工作，但加密副本可能无法再解密显示。

“永不过期”只取消时间自动失效；后台撤销仍立即生效。
