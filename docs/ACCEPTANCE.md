# 上线验收清单

每项记录日期、版本 SHA、环境和结果。CI 通过不等于 E5 已部署。未执行项保持未勾选，不填写推测结果。

## 自动化可验证

- [ ] Python、JavaScript、Shell 语法检查通过。
- [ ] 实际 MySQL 8.4 Alembic upgrade/check 通过。
- [ ] API 的登录、CSRF、角色、Key 范围与撤销、登记幂等性、草稿版本冲突、导入冲突、发布、失败恢复记录与历史回滚测试通过。
- [ ] 单元测试验证多 unit 启停依赖顺序、disable 不 stop、保留关键基础服务。
- [ ] 实际 Nginx HTTP 请求/查询参数/正文、鉴权、管理令牌剥离、SSE 首段实时到达、WebSocket 握手与消息回传测试通过。

## 统一入口追加

- [ ] 从外部仅能访问批准的 TCP 80/443；19092/19093、MySQL 和业务端口不可达，IPv6 安全组也检查。
- [ ] 80 对已登记域名只返回 HTTPS 跳转；未知 Host 不跳转、不代理。
- [ ] 同一 443 上管理域名与不同业务域名分别使用正确证书及客户端 CA；错误 SNI/Host 组合无法跨域访问。
- [ ] 原系统 Nginx 不与 edge 抢占 80/443；未自动关闭 SSH 或现有服务；私有救援入口已验收。

## 远程场景追加

- [ ] 动态 IP 模式下，同一有效管理证书从两个不同来源连接可到达登录；缺失/错误/吊销证书仍被拒绝。
- [ ] 可选 IP 白名单开启时，即使证书有效也不能从未授权来源进入；升级旧策略不会自动放宽访问。

- [ ] 完成 `REMOTE-SECURITY.md` 全部上线阻断项；从另一台机器验证内网端口不可达。
- [ ] 管理域名与业务隔离；mTLS 缺失/错误/吊销证书均被拒绝，Secure host-only Cookie 和 Origin 规则生效。
- [ ] 检查 root 日志目录不可被 Web 用户写入；模拟 interrupted journal 后重启，未完成配置不能激活。
- [ ] 敏感操作超过 5 分钟触发重新验证，闲置 30 分钟登录失效。

## E5 现场必须执行

- [ ] 记录原 Manager 版本、配置、原有入口、当前服务/任务、MySQL 备份；确认新端口空闲。
- [ ] 新控制台、Agent、edge 的文件所有者和权限正确；Web 用户无任意 sudo/systemctl/策略写入权。
- [ ] MySQL 断连/认证错误可以明确定位，连接恢复不会重置管理员或配置。
- [ ] HTTP 健康失败时仍正确展示真实 systemd 状态，避免误报服务停止。
- [ ] 未登录管理接口返回 401；控制台公开入口禁止访问 /internal/auth；未携带内部密钥的直接鉴权请求被拒绝。
- [ ] 新 API 不因伪造 Host/X-Forwarded-For/X-E5-Confirm 获得本机免登录能力。
- [ ] 旧动态资产导入先预览，不覆盖同名冲突；静态资产的 health_url 从实际配置核对。
- [ ] 在可中断的测试服务上完成页面启动、停止、重启、启用/禁止自启。正在生成视频/音频的业务不得用来试停。
- [ ] disable 不停止进程；注销不删除 unit、程序、数据库、模型、音视频和工作区。
- [ ] 每个实际服务通过统一 443 域名入口完成登录、静态资源、页面刷新、重定向、Cookie、API、上传下载测试。
- [ ] 实际 Harness SSE 和 ComfyUI WebSocket 不被缓冲；长时间无心跳的上游超时符合设置。
- [ ] 配置测试 IP 白名单、API Key 与来源限流；不靠扩大为公网白名单通过验收。
- [ ] 用独立测试端口制造占用/配置失败，确认新发布失败且旧入口继续可用；确认 pending 核对逻辑。
- [ ] 成功发布两次，再历史回滚，确认新旧入口状态、摘要和 MySQL active 一致；草稿未被覆盖。
- [ ] 配置并实际验证 HTTPS 证书信任、主机名、私钥权限和续期后的重载。
- [ ] 重启新控制面、edge 与测试服务，持久数据仍在；确认旧 Manager 与旧入口没受影响。
- [ ] 日志轮转正常，访问采样没有 Cookie、Authorization、网关 Key、查询参数或请求体。
- [ ] 安装升级失败能恢复旧 release/unit/控制台配置；数据库备份可恢复。

## 完成后才切流量

验收前保留新旧入口并行。逐个服务切换客户端地址，每次保留旧入口回退。不要一次切全部服务，也不要因为网关发布成功就删除旧配置。代码按用户授权合并到 `main`；合并不代替现场上线验收。

## 完整安装器追加验收

- [ ] 全新 Ubuntu 24.04 上检查 apt 安装、原 policy-rc.d 恢复、新系统 nginx 不抢占 edge 端口。
- [ ] sg_runtime 无 DDL 权限，app.env 与 migrate.env 分离；同名未知库/账号不被覆盖。
- [ ] 实际域名完成 staging dry-run 和生产 Let's Encrypt 签发；未验证域名不能激活 HTTPS。
- [ ] HTTP-01 随机文件可访问，点文件/符号链接/目录不可访问，443 不因续期被停止。
- [ ] 从管理员电脑导入 p12 后登录；没有/错误客户端证书无法登录。
- [ ] 专用 renew.timer 可触发；模拟证书部署失败，检查恢复记录和下一轮重试。
- [ ] 同参数重跑不改密码/CA/路由；升级前备份存在且可以恢复。
- [ ] CA 加密恢复包和口令异地保管；确认自动 CRL 任务，并另行监控、维护浏览器证书期限。

## 本轮后台与自动运维

- [ ] 普通 Web 用户能够读取访问采样，重启 Agent 后仍可连接；其他 UID 不能连接 socket。
- [ ] CRL 定时器实际启用，手工触发成功；私钥/解密凭据/恢复包不可被 Web 用户读取。
- [ ] CRL 更新保留吊销记录，不轮换浏览器身份；失败/重启恢复经过演练。
- [ ] 只有管理员在密码与 CSRF 校验后能下载加密 P12；初次登录仍需要原 mTLS 引导。
- [ ] 用户修改自己的密码后所有设备会话失效，旧密码被拒绝，API Key 不变。
- [ ] 服务表单可增减 unit，本机登记幂等，越权 Key 和未批准服务被拒绝。


## 路由权限与业务用户追加

- [ ] 后台新增/复制路由的“所属服务”只能从已登记服务下拉选择，不能手填陌生 service id。
- [ ] `service_auth` 在远程 HTTPS 业务域名可用；不要求 Gateway API Key、mTLS 或微信 Token，但仍保留 CIDR、限流、连接数、body、timeout、upstream 白名单和管理凭据剥离。
- [ ] `service_auth` 保留业务自己的 Authorization/Cookie，且客户端伪造的 `X-SG-User-ID`、OpenID、Gateway Key、内部 Secret 不会透传为可信身份。
- [ ] 父路由 `/api/` 为 `service_auth`、子路由 `/api/private/` 为 `wechat_user` 时，`/api/private/profile` 必须微信鉴权。
- [ ] 无尾斜杠请求 `/api/private` 不能回落到公开 `/api/`，而应内部归一后执行 `/api/private/` 的下级权限。
- [ ] 更深层路由继续覆盖父级，例如 `/api/private/admin/` 可改为 API Key 或 mTLS，且不会继承父级微信权限。
- [ ] 复制 mTLS 路由并改为 API Key、微信或业务透传后，保存请求不再携带旧 `client_ca`；直接 API 提交残留 `client_ca` 仍被 422 拒绝。
- [ ] 复制带 `route_secret` 的路由后，新副本默认 `upstream_auth=none`，原路由保持不变，Secret 不复制。
- [ ] 草稿显式启用 `route_secret` 但未配置 Secret 时，发布预览直接阻止发布并列出缺失 route id。
- [ ] 微信登录成功后 Token 只属于当前服务；跨服务 Token、过期 Token、停用用户和角色不匹配均不能访问 `wechat_user` 路由。
- [ ] 业务后端从可信头获取 user id/role/OpenID；loopback introspection 还要求正确 `user_service_ids` 专用 Key，其他 Key 作用域不能替代。
- [ ] 微信 AppSecret 不出现在 MySQL、网页、路由快照、日志或 API 响应；微信 `session_key` 不保存、不下发。
- [ ] 管理页面和 `/static/*` 返回 no-store；升级后刷新即可看到新路由鉴权选项，不继续使用旧缓存脚本。


## API Key 可恢复显示追加

- [ ] API Key 新建后在管理员后台可再次查看完整明文，并可一键复制。
- [ ] MySQL 中 `token_hash` 与 Key 明文不同；`token_ciphertext` 也不包含可直接搜索到的明文。
- [ ] 用错误 key id 或错误 auth-secret 无法解密密文。
- [ ] 旧版 hash-only Key 继续可以鉴权，但后台明确显示“不可恢复”，不会伪造一个替代值。
- [ ] 撤销可恢复/永不过期 Key 后立即无法鉴权。
- [ ] API 密钥列表与相关管理 API 返回 `Cache-Control: no-store`，访问采样与审计日志不记录 Key 明文。
