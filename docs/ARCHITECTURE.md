# 架构、状态与安全边界

## 三层职责

控制面负责 MySQL 状态、用户登录/权限、服务登记、路由草稿、发布和审计。浏览器只访问控制面 API。数据面是独立 Nginx 实例，直接连接业务上游，承载 HTTP/WebSocket/SSE/大文件。root Agent 是受限本机执行器，不接收远程 TCP，不提供 shell，仅对明确批准的服务和网关配置操作。

数据库不是 root 授权源。即使管理账号被滥用，也不能通过修改数据库添加未获本机批准的 unit/上游/端口。Agent 每次读取 root-owned policy 与旧 E5 root-owned 注册文件，独立校验安装位置、用户和结构化配置。此边界不把已经由 root 批准的业务 unit 视为不可信任意代码；root 批准前必须审核 unit、drop-in 和程序目录权限。

## MySQL 表

`users` 保存密码哈希与角色；`login_sessions` 保存会话哈希、CSRF 与到期时间；`api_keys` 保存令牌哈希、范围、失效时间和撤销状态；`services` 与 `routes` 保存规范化 JSON 草稿；`gateway_state` 保存全局草稿版本及 active/pending release；`releases` 保存不可变配置快照、摘要和发布结果；`health` 保存最近健康状态；`audit` 保存控制操作记录。

关系数据采用外键和唯一约束。会话/Key 明文不入库。Alembic 0001 冻结初始建表语句，应用启动不自动建表。Web API 不提供审计删除接口；具有数据库管理员权限的人仍能修改表，当前版本不宣称密码学防篡改。

## 发布状态机

```text
草稿 revision=N
   ↓ 预览：snapshot + digest
校验相同 revision/digest
   ↓ MySQL 提交 pending
Agent 复验 root policy → nginx -t → 原子写配置 → reload
   ↓ 各监听入口与本机状态端口返回目标 digest
核对实际 digest → active / failed / 保持 pending 等待人工核对
```

配置摘要用于内容一致性，不是身份凭据。用 MySQL pending 记录先于主机变更，避免主机变更完成但数据库没有恢复线索。reload 返回码本身不能证明新监听已生效，因此另做配置指纹与监听检查。失败不能确认时不宣称回滚成功。

控制面必须单 worker 运行；本地 Agent 使用互斥锁串行控制。当前不是分布式事务或多节点控制器。旧长连接在 Nginx graceful reload 后可继续由旧 worker 服务，不会因保存草稿而重建连接。连接中的鉴权不持续重复执行，撤销 Key 仅保证后续新请求被拒绝。

## 安全默认值

默认私有网段访问、会话鉴权、禁止 public route、不允许 DNS 解析任意上游、不允许用户输入 raw Nginx 指令、不允许远端控制任意 unit。API 不接受业务环境文件路径、数据库密码或任意命令。root policy 文件不能被 Web 服务写入。

会话 Cookie 是 HttpOnly + SameSite Strict；更改接口验证 CSRF。登录有控制面有界限速和控制台 Nginx 的来源 IP 限速。API Key 使用独立 `X-Gateway-Key`，不占用业务的 `Authorization`。上游不应收到网关自己的管理令牌。新网关与旧 E5 会话是不同认证系统，迁移期可按路由选择旧 E5 auth_request。

不建议把同一宿主域的任意第三方应用与管理 Cookie 混在一起；Cookie 不按端口隔离。不同信任等级的业务必须使用隔离域名，控制台 Cookie 默认不共享父域。不能仅靠端口不同把不可信第三方应用变成安全租户隔离。

## 明确边界

本版本没有完整多租户、WAF、主动熔断器、分布式限流、全量时序指标和业务访问历史检索。Nginx 使用被动上游失败检测；HTTP 健康轮询显示健康度，不会主动摘除业务实例，避免轻率探测造成误切换。远程上游只做流量代理，不提供远程 systemd 生命周期管理。

生产证书、管理员恢复凭据、MySQL 备份与主机级防火墙由部署者负责。控制台/数据库故障时新鉴权请求会失败关闭；继续开放旧鉴权缓存并非默认行为。MySQL 与 Agent 的不可用状态不应显示为“所有业务停止”。
