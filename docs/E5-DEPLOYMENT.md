# E5 部署与迁移

## 0. 先并行部署，不接管旧服务

基于已有 E5 接入规范：旧 Manager 内部端口为 `18090`，旧动态登记目录为 `/etc/e5-business-manager/assets.d/`。这些是已有文档中的基线，不是本次远程探测结果。部署前用本机配置核实。

第一轮不替换旧 Manager，不动其端口 80，不修改原有业务 Nginx 站点，不自动停止 ComfyUI、Harness、视频或音乐任务。不把新网关自身加入可启停资产，避免从网页停掉管理入口。

建议由本地 Codex 在 E5 的独立工作目录执行。必须以已审核的代码运行 root 安装器；不要使用 curl|bash，不把 MySQL 密码写到聊天或 GitHub。

## 1. 检查前提

需要 Ubuntu/systemd、Python 3.12+ 与 venv、Nginx（含 auth_request 模块）、MySQL 8.0/8.4、curl。脚本不会修改系统软件仓库，不会擅自替换已安装的 MySQL。建议使用现有 MySQL 实例中的全新数据库。

```bash
python3 --version && nginx -V && systemctl is-active mysql.service
```

```bash
sudo ss -ltnp
```

检查 `19091`、`19092`、`19093` 与计划使用的 `19100..19119` 是否空闲。端口冲突要先调整并审核对应 unit/策略/控制台配置，不能杀掉占用端口的原服务。

## 2. MySQL

参考 `deploy/bootstrap-mysql.sql`，由数据库管理员在本机建立独立 `servicegateway` schema 与用户。替换密码占位符后在安全终端执行；不要提交修改后的含密码 SQL。

迁移需要建表、索引、外键与 ALTER 权限；运行时可以另建只有 SELECT/INSERT/UPDATE/DELETE 的账号，迁移与运行账号应分开管理。所有数据库变更前备份。SQL 模板使用 `127.0.0.1` 用户 Host；与 URL 使用的实际连接方式保持一致。

```bash
sudo bash deploy/install.sh
```

首次生成 `/etc/servicegateway/app.env` 后编辑：

```bash
sudoedit /etc/servicegateway/app.env
```

`SG_DATABASE_URL` 格式：`mysql+pymysql://用户名:URL编码后的密码@127.0.0.1:3306/servicegateway?charset=utf8mb4`。URL 中的 `@ : / # %` 等密码字符必须正确编码。不要 `source` 该文件或用 shell eval 读取凭据。

纯可信局域网 HTTP 调试使用 `SG_SECURE_COOKIE=false`。正式 HTTPS 控制台应改为 `true`，配置受信任证书，不能开放公网明文登录。Cookie 默认 host-only；跨子域统一登录需要管理员评估域隔离后设置 `SG_COOKIE_DOMAIN`，不要给不可信子域共享会话。

## 3. 安装与管理员

```bash
sudo bash deploy/install.sh
```

脚本创建非 root 服务用户、不可变 release、独立业务目录，先迁移数据库再切换版本；失败恢复旧运行代码与自有配置，保留数据库和业务数据。部署完成会打印创建管理员的单行命令。也可使用：

```bash
sudo systemd-run --quiet --wait --pty --collect -p EnvironmentFile=/etc/servicegateway/app.env -p WorkingDirectory=/srv/e5-apps/servicegateway/current /srv/e5-apps/servicegateway/current/.venv/bin/sgctl admin rffanlab
```

密码交互隐藏输入，不放在命令参数中。入口：`http://你的E5地址:19091/`。默认网段是 `192.168.1.0/24`，与现场不符时在本机调整 `nginx-console.conf` 和 root policy 的允许网段。不要配置 `0.0.0.0/0` 作为临时排障方案。

## 4. 导入现有资产

控制台“导入 E5”读取 root-owned 动态登记，先显示 JSON 清单，再预览新增、冲突和保持不变项；不会自动覆盖同名不同配置，不创建路由，不接管旧端口。

旧 `ASSETS` 内置资产不是动态注册文件，不能假定能自动发现。可通过管理员会话导出旧 `/api/overview` 到本机 JSON，再执行：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl export-e5 --overview-file /安全目录/e5-overview.json
```

仅提取 manifest 字段；缺失 `health_url` 的资产会跳过并提示，不会推断上游端口，也不会 import/exec 旧 `app.py`。补齐真实健康地址、unit 顺序和原入口后再导入。不要把含 Cookie/密钥的原始响应提交仓库。

未在旧 root-owned 注册表中的服务，需要本机管理员批准已安装 manifest：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl approve /安全目录/service-registration.json
```

批准器核验本地明确 unit、root 所有权和非 root 运行用户，写入 root policy。Web API 不具有写 policy、unit 或 sudoers 的权限。多上游/远端受信任 HTTP 地址需要管理员在本机审核添加 `policy.json` 的对应服务 `upstreams`；不能扩大成任意地址代理。

新平台注册接口使用管理员登录 + CSRF 或限定服务注册 Key；不会沿用旧本机无 Token 例外。原 manifest 字段兼容，认证机制需显式调整。

## 5. 创建一个路由

选择已登记服务，先用空闲新端口代理根路径 `/`。选择 `e5` 可继续复用旧登录态；选择 `session` 使用新控制台会话；自动化调用使用 `api_key`，通过 `X-Gateway-Key` 传入。应用本身的 Authorization 头仍传给业务，不被网关 Key 占用。

HTTP 上游使用已批准的 IPv4 地址/端口。默认关闭响应缓冲、启用 WebSocket、读取/发送空闲超时 300 秒。这个超时不是任务总时长；持续发数据的 SSE 可长期保持。上游长时间不发送任何数据则应根据业务调整心跳或超时。

保存草稿 → 预览生成配置 → 检查认证、端口和上游 → 确认发布。当前版本不执行任意用户编写的 Nginx 片段。

不要对不支持子路径的应用直接配置 `/app/` 后期待所有静态资源、跳转和 Cookie Path 自动适配。ComfyUI/Harness 等业务先走独立端口或专用域名，再针对性验证路径代理。

## 6. TLS

本机管理员安装证书到 `/etc/servicegateway/certs/<证书ID>/fullchain.pem` 与 `privkey.pem`，目录与文件 root 所有且不可被非 root 写入。前端仅填写证书 ID，不允许上传任意路径或读取私钥。私钥不得进入 Git、审计或日志。

所有共享同一端口的路由目前必须使用同一证书。证书续期由主机既有维护流程负责；更新文件后重新发布并确认实际证书生效。不包含自动 ACME、DNS 插件或证书签发账户管理。

## 7. 回滚和故障核对

网关业务发布失败会恢复专用 Nginx 旧配置；若控制台/Agent 通讯中断导致结果不确定，MySQL 保留 pending，禁止盲目再次发布。使用“核对发布状态”读取实际 Nginx 指纹，再确定成功或失败。

历史回滚只恢复成功的网关快照；不会改变业务数据、回滚程序版本或覆盖当前草稿。删除草稿路由后，必须发布删除，再注销仍被线上路由引用的服务。

安装器部署失败的代码回退与“网关配置历史回滚”是两件不同的事。数据库迁移不执行破坏性自动 downgrade；MySQL 备份需要独立验证恢复。

## 8. 本机查看日志

```bash
sudo journalctl -u servicegateway.service -u servicegateway-agent.service -n 100 --no-pager
```

```bash
sudo journalctl -u servicegateway-edge.service -n 100 --no-pager
```

```bash
sudo bash /srv/e5-apps/servicegateway/current/deploy/verify.sh
```

交付给本地 Codex 的要求：按本文逐步执行，先备份并并行部署；补齐真实资产清单，跑 `docs/ACCEPTANCE.md`，记录测试结果，不绕过 root 白名单，不停用旧 Manager，不把密码打印到聊天。真实业务验收前不要合并主分支或切换旧入口。
