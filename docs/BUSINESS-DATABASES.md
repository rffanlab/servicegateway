# 业务数据库：后台建库与本机部署授权

这一模块补齐“像 E5 服务管理一样，为本机业务创建数据库”的能力。不是给网关 Web 运行账号增加 `CREATE ON *.*`，也不是开放 MySQL 公网访问。仍只通过 80/443 访问后台；MySQL 和业务原始端口维持内部监听。

## 1. 已有服务器升级和首次启用

在项目目录更新并只升级应用，不重新安装 MySQL、签发证书或重置数据：

```bash
cd ~/servicegateway && git fetch origin && git switch main && git pull --ff-only origin main && sudo bash deploy/install.sh
```

升级会重启管理 API 和本机 Agent，管理请求可能短暂中断。新模块不需要修改网关自身数据库表结构。保留现有备份和可用 SSH/私有救援通道。

本机管理员明确授权一次建库能力：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl database-enable
```

默认通过 `/run/mysqld/mysqld.sock` 使用 MySQL root 的本机 socket 认证。脚本不会更改 MySQL root 密码、开放 3306 或授予网关运行账号全局权限。若现有 MySQL 管理账号要求密码，改用隐藏输入：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl database-enable --ask-password
```

需要明确指定其他已有 MySQL 管理账号时，增加 `--admin-user 账号名`。只有具备创建库、创建账号、授予所需权限能力的账号才能启用；不会自动给该账号提权。仅支持当前部署约定下的本机 MySQL 8.0/8.4、3306，不自动适配 MariaDB、远端数据库或改变主机监听。

管理连接配置位于 `/etc/servicegateway/database-admin.json`，root 所有、0600。默认 socket 认证不保存数据库 root 密码；密码认证模式会把管理口令写入这一 root-only 文件。不要给 Web 账户读取它的权限，不要复制到项目目录或聊天。它是本机在线管理授权，不声称能抵御 root 失陷。

## 2. 后台创建业务库

管理员登录后进入 **业务数据库 → 创建业务库**，选择已登记的服务，填写库名。服务卡片也有“建业务库”按钮。

库名必须以 `sgb_` 开头，只允许小写英文字母、数字和下划线，例如 `sgb_myapp`。每个服务目前对应一个库。这个独立命名空间不会与 `servicegateway`、`mysql`、`sys`、`performance_schema`、`information_schema` 重叠。表单只提交服务 ID 和库名，不接受任意 SQL、权限列表、数据库地址或 root 密码。

创建服务必须先获得本机授权。可以在业务程序尚未启动时先安装非 root systemd unit、批准和登记服务，再建库、迁移表结构，最后启动应用，避免“启动需要数据库、建库又必须先启动”的循环。

创建立即生效，不是等待网关发布的路由草稿。默认字符集 `utf8mb4`、排序规则 `utf8mb4_unicode_ci`。系统生成两个不同的随机密码账户，用户名由服务 ID 稳定派生，账号 Host 只使用 `127.0.0.1`。

| 账号 | 权限与用途 |
|---|---|
| runtime（运行账号） | 仅该库的 SELECT、INSERT、UPDATE、DELETE，用于程序日常读写 |
| migration（迁移账号） | 该库的读写和 CREATE、ALTER、DROP、INDEX、REFERENCES、CREATE VIEW、SHOW VIEW，用于程序建表、结构迁移 |

**迁移账号有 DROP 权限，也能够删除自己的整个业务库；它不是无损只读账号。** 不能给出“有删表权限但绝不可能删本库”的错误保证。两类账号都不授予其他库、系统库、CREATE USER、FILE、SUPER 或 GRANT OPTION 权限。每个账号默认同时连接上限为 32；这不是磁盘配额、全实例资源隔离或分布式限流。

MySQL 库级 GRANT 中的下划线可能是通配符，代码根据 `partial_revokes` 的实际设置使用准确的授权写法，并验证 SHOW GRANTS，避免 `sgb_myapp` 意外匹配其他库。程序本身不修改全局 `partial_revokes`。

普通 viewer/operator、服务登记 Key 和路由访问 Key 都没有建库权限。后台管理员创建时保留 CSRF 和最近五分钟密码重验机制；本机 Agent 再检查 root 授权及明确的非 root unit。修改 Web 数据库登记不能代替本机授权。

## 3. 获取连接配置

在业务库列表点击“下载连接配置”，选择运行或迁移账号，重新输入**当前网站登录密码**，下载私有 `.env` 附件。列表、普通创建响应和操作审计不返回密码；附件使用 `no-store`，没有匿名固定下载链接。

连接配置包含 `DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD/DB_CHARSET` 和完成密码 URL 编码的 `DATABASE_URL`。`127.0.0.1` 指业务所在服务器本机，不是 Windows 电脑，也不是容器宿主机的自动别名。容器或其他机器访问需单独审核网络方案，不能直接把账号 Host 改为 `%`。

程序会在启动时自动建表的，先用 migration 账号完成初始化，再改用 runtime。下载账号配置不会修改程序已有 `.env`，也不会自动迁移旧数据。MySQL 管理账号和网关自身数据库密码不会从此入口下载。

## 4. 本机部署小弟使用命令

先准备真实 manifest，参考仓库 `examples/service-registration.json`。已有本机业务可以一次批准并登记：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl register /实际路径/service-registration.json --approve
```

假设真实服务 ID 为 `myapp`，创建其独立业务库：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl database-create --service myapp --name sgb_myapp
```

本机 CLI 需要 root，直接复核主机批准的 unit；即使尚未在后台登记，只要本机授权存在，也允许为已安装但未启动的服务准备数据库。后台表单则要求先登记，以便选择正确的业务。

查看本平台建库记录，不打印口令：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl database-list
```

导出新私有文件，不覆盖已有凭据：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl database-credentials --service myapp --account runtime --output /root/myapp-db-runtime.env
```

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl database-credentials --service myapp --account migration --output /root/myapp-db-migration.env
```

目标目录必须由 root 所有且不可被其他用户写入，文件为 0600，不跟随符号链接、不覆盖现存文件。按照业务部署规范用 systemd EnvironmentFile 或安全配置方式加载；不要 `source` 成任意 Shell 脚本，也不要为了程序可读而改成 777。

## 5. 幂等、失败和备份

相同服务、库名、授权再次提交，会核对已有库、账号和授权，返回 `changed=false`，不执行重新授权或重置密码。任何已有同名但不属于本平台的库/账号，都拒绝接管；系统不会靠 `IF NOT EXISTS` 跳过这个冲突。

MySQL 创建库、创建用户、授权等语句会隐式提交，不能假装一个普通事务可以回滚整个过程。执行前保存 root-only 意图和阶段记录，新用户先锁定，两个账户授权完成并核验后才解锁。中断/失败保留库和记录，尽可能锁住本轮确认创建的账号，标记 `needs_review`，不自动 DROP、不盲目重试 DDL。断网发生在某一步的响应之前时，也按不确定状态保留现场。

此状态需要本机管理员按阶段日志和实际 MySQL 状态核对，不是靠删 `bootstrap.json`、重装 MySQL 或清库解决。当前不提供自动修复、旧库接管、数据库删除、密码轮换或任意 SQL 控制台。

建库记录和可恢复业务密码位于 `/etc/servicegateway/business-databases`，目录 0700、文件 0600。数据库列表显示这些管理记录，不是实时数据库存活/业务内容扫描；外部管理员改过业务口令时不会自动重置，下载的已保存连接配置也不会自动同步外部改密。

备份必须覆盖 **业务 MySQL 数据 + 上述私有记录 + 管理连接配置**，并加密保存到异地。网关程序升级/路由回滚不会回滚业务数据库，注销服务也不会自动删库。删除服务登记不释放历史建库名或覆盖凭据。

## 6. 验收

自动化验证包含 API 角色/CSRF/密码/登记 Key 边界、输入校验、秘密不进入列表/审计、同名冲突、幂等和中断保护。CI 另在独立 MySQL 8.0、8.4 容器中通过真实本机 socket 执行生产建库代码，验证运行/迁移账号真实登录、DML/DDL 分离、下划线授权隔离、跨库/转授权拒绝及部分 DDL 保留。只有测试进程会清理其预先确认不存在、带随机标识的测试资源，不用于用户主机。

目标服务器仍应创建一个专用测试业务，核验连接、建表、正常读写和凭据权限后再使用。自动测试不能代替业务备份恢复和目标服务器验收。

参考：MySQL 8.4 GRANT、CREATE USER、隐式提交说明：

- https://dev.mysql.com/doc/refman/8.4/en/grant.html
- https://dev.mysql.com/doc/refman/8.4/en/create-user.html
- https://dev.mysql.com/doc/refman/8.4/en/implicit-commit.html
