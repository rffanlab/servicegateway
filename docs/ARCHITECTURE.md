# 架构、状态与安全边界

远程部署要求以 [REMOTE-SECURITY.md](REMOTE-SECURITY.md) 为准。

## 三层职责

控制面负责 MySQL 状态、身份、服务登记、路由草稿、发布与审计。独立 Nginx 数据面直接连接业务上游，承载 HTTP/TLS/WebSocket/SSE，不让 Python 转发业务内容。root Agent 只有本机 Unix socket，验证对端 UID，只执行已批准的结构化操作。

数据库不是 root 授权源。管理员账户不能仅靠修改数据库获得未批准的 unit/上游/端口权限。root policy 和 unit/drop-in 必须不可被业务账户写入。root 批准前仍需人工审核业务程序、依赖和目录权限；本系统不是任意不可信代码的沙箱。

## MySQL

users 保存密码哈希和角色；login_sessions 保存会话哈希、CSRF、绝对期限、最近活动和重验时间；api_keys 保存令牌哈希、范围和撤销状态；services/routes 是配置草稿；gateway_state 保存草稿版本及 active/pending；releases 保存快照与状态；health 保存最近健康检查；audit 保存控制操作记录。

Alembic 管理迁移，应用启动不自动建表。0002 使旧会话重新登录。不存在通过 Web 清库、删除业务数据或删除审计的 API；数据库管理员仍能修改表，当前不声称审计具有密码学防篡改能力。

## 发布状态

预览取得 revision/digest → 校验一致性 → MySQL 写 pending release → Agent 复验 root policy → nginx -t → 落盘旧配置和 pending journal → 原子替换 → reload → 检查配置摘要和唯一 release generation → 确认 active/failed，或保留未决记录。

单看 reload 返回码或相同配置摘要不足以证明新 worker 已加载。每次发布使用唯一 generation，同配置证书更新也必须确认该轮加载。中断恢复由 root 落盘记录和 MySQL 状态共同核对；无法确认时拒绝盲目重试。edge 启动前恢复未完成 candidate，防止重启意外上线半成品。

历史回滚只改变网关快照，不回退业务程序/数据库、不覆盖编辑草稿。服务注销不删除 unit、模型、音视频或工作区。多 unit 正序启动、逆序停止，restart 为逆序 stop 后正序 start；disable 不停止当前进程。

## 身份和网络

内部组件绑定 loopback。统一 edge 启用后独占 80/443，80 仅为已登记主机名做 308 跳转，443 的管理域名由 root policy 固定生成，业务域名由数据库路由管理。证书/客户端 CA 一致性按 (端口, 域名) 校验，不能跨域套用 TLS 身份；未知 SNI 拒绝握手，SNI 与 Host 不一致拒绝请求。初始证书未准备时不启用外部入口。远程模式管理域名与业务域名分离，使用 Secure host-only 管理 Cookie。远程业务路由使用 API Key 或 mTLS，旧 E5 会话兼容仅在显式 LAN 策略下启用。网关不把管理 Cookie/内部凭据转发给业务。

鉴权请求携配置摘要，旧 worker 不能使用新版本较弱的授权规则。管理 API/数据库不可用时，依赖这些组件鉴权的新请求失败关闭；mTLS 在 Nginx 层验证。已建立长连接不会持续重新鉴权，凭据撤销不自动断开连接。

## 范围

单主机、单控制面 worker，Agent 串行发布；不是分布式事务或多节点控制器。健康轮询不自动摘除上游，负载均衡使用 Nginx 被动失败检测。访问采样不是全量时序监控。业务自己的权限、CSRF、任务配额和文件安全仍需独立保证。

证书生命周期、备份恢复、依赖锁定/扫描、云安全组与主机防火墙由目标环境验收。测试不能代替现场配置检查或独立渗透测试。
