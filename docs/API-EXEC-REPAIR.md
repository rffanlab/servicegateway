# 管理 API 的 203/EXEC 权限错误

## 本次现场证据

Nginx 的临时目录补齐后已 `Started`，Agent 也已启动；当前阻断是：

```text
Failed to execute .../.venv/bin/uvicorn: Permission denied
Main process exited, code=exited, status=203/EXEC
```

随后反复连接 `127.0.0.1:19092` 失败是结果，不是根因。不需要开放这个内部端口，也不是重新签发证书可以解决的问题。回滚后的 `LoadState=not-found` 是安装器移除了新 unit，不能据此否认前面的启动记录。

源码中完整安装器使用 `os.umask(0o077)` 保护凭据，但此前创建 venv/pip 的子进程也继承该掩码。新环境目录会成为 0700，安装的脚本可能成为 0700；后续只执行 `chmod -R go-w` 不会给非 root 运行用户补充读取/执行权限。真实普通用户执行试验已复现该问题。现场日志确定执行被拒绝，但没有给出逐级文件 mode；修复后新增 namei/mount 诊断继续区分父目录权限、noexec 或其他主机策略，不能为排障关闭隔离。

## 修改范围

仅创建新 release 的 Python 环境与安装代码时，在子 shell 中使用 `umask 022`；主安装流程继续 `umask 077`，数据库凭据、备份和证书私钥不放宽。代码仍 root 所有、业务用户不可写。管理服务继续以 `servicegateway` 用户运行，并用 venv 的 `python -I -m uvicorn` 启动；不使用 root 运行 Web，不执行全盘 chmod 或 777。

在切换 current/启动服务之前，以实际 `servicegateway` 用户及严格 systemd 沙箱验证执行文件、应用/依赖导入、静态资源、内部鉴权密钥可读性和迁移后的数据库。环境文件由 systemd 读取，服务用户不需要直接读取 root-only app.env；检查只读，不改库、不创建账号、不启停业务。

本次还修复诊断保存：报告默认改为 `/etc/servicegateway/deploy-reports/`（root-only 0700；报告 0600），不依赖发行版可能允许日志组写入的 `/var/log`，也不修改 `/var/log` 权限。保存失败时输出已经脱敏的诊断，不丢掉第一现场。journal 保留时间戳，回滚后尝试检查最后一个受管 release 的路径和挂载选项。

## 在服务器上继续

先在仓库中更新，保留本地修改；Git 提示冲突时不要强制 reset。

```bash
git fetch origin && git switch main && git pull --ff-only origin main
```

用原参数重跑完整安装器，新 release 会创建正确权限的环境，保留 bootstrap.json、数据库和凭据。

```bash
sudo bash deploy/full-deploy.sh install --domain service.vfuai.com --email admin@rffan.com --agree-tos
```

不要删除 `/etc/servicegateway`、`/var/lib/mysql` 或手工重新生成数据库密码。不要为绕过错误把 servicegateway 用户改成 root、关闭 ProtectSystem 或执行 `chmod -R 777 /srv`。

失败时使用：

```bash
sudo python3 -I deploy/diagnose.py
```

报告含路径权限和时间戳，不输出完整配置；分享前仍需检查。读诊断不等于完成修复。安装成功后再检查证书签发、实际 HTTPS 登录和外部端口。

## 验证范围

新增回归测试校验作用域 umask、私有文件权限、诊断保存和失败回退输出。Ubuntu Actions VM 另有真实非 root systemd 冒烟测试：私有 umask 下的旧 venv 不能执行；使用安装器原代码片段创建并安装新 wheel，验证新 API、数据库连接、静态文件、未登录 401，以及用户不能读取 app.env/诊断报告、不能写入代码。测试使用独立临时路径、临时用户和 servicegateway_test 数据库，不代表已在目标服务器部署。
