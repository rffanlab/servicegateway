# 首次部署：edge 启动失败、Agent/API 随后失败

## 目前可确定与不可确定的事实

2026-09-19 收到的现场日志显示：包安装、Python wheel 安装和部署预检已经通过；`servicegateway-edge.service` 首先启动失败，随后 Agent/API 失败；安装器回滚且没有进入证书签发阶段。该日志没有带 journal 或 Nginx 的底层错误行，不能据此断言现场唯一根因。

源码检查及隔离复现发现一处确定缺陷：生成器仅显式设置 `client_body_temp_path` 与 `proxy_temp_path`，遗漏 `fastcgi_temp_path`、`uwsgi_temp_path` 和 `scgi_temp_path`。发行版 Nginx 会使用编译时默认目录，首次启动可能尝试在 `/var/lib/nginx/` 下创建它们；该路径不在 edge 的 `ProtectSystem=strict` 写入白名单内。此前普通 nginx 进程测试没有验证这个 systemd 挂载边界。

修复显式指定全部五类临时目录到 `/var/lib/servicegateway/edge/`；保留严格沙箱，不允许写整个 `/var`、不改为 root Web 服务、不关闭认证。

## 重试

在原项目目录更新 main。若 Git 提示本地改动冲突，先保留改动，不使用 reset --hard 或 git clean。

```bash
git pull --ff-only origin main
```

先收集这次失败的底层原因，命令是只读操作，不会查询数据库或打印环境文件：

```bash
sudo python3 -I deploy/diagnose.py
```

随后使用原来的真实域名和邮箱重跑完整部署，不新增固定出口 IP 参数。不删除 `/etc/servicegateway`、`/var/lib/mysql` 或 bootstrap.json；它们保存已建立的凭据和安装归属。

```bash
sudo bash deploy/full-deploy.sh install --domain service.vfuai.com --email admin@rffan.com --agree-tos
```

完整安装器保留已经初始化的数据库及账号，重跑前按原流程备份。失败后留存的旧 nginx.conf 会在 edge 的 ExecStartPre 内进行受限、幂等修复：仅补齐遗漏临时目录，先 nginx -t、保存 root-only 原配置副本，再原子替换；不改业务路由、域名、证书或鉴权。发现未知自定义目录或未完成恢复记录时停止，不覆盖。对已运行的 master 不在线偷偷改配置；后续正常发布使用新的生成器。

## 诊断与回滚

现在将 enable 与 start 分开检查。发生错误后，在停止进程/删除首次部署 unit 前保存诊断到 `/var/log/servicegateway-deploy/`（0600 文件），保留首次失败的 unit 状态、有限 journal、nginx 构建参数和 error log 尾部。不会打印 nginx -T、完整配置、数据库连接内容或证书私钥。

日志过滤已知本机密码和常见凭据模式，但分享前仍应检查报告。回滚后当前 unit 可能已不存在，这不等于 journal 一定消失：诊断命令仍按名称读取本次开机的历史记录。主机重启后若日志未持久化，旧记录可能不可用。

`tat_agent.service` 的旧 PIDFile 路径提示以及 policy-rc.d 禁止包自动启动，不足以说明它们导致了网关失败；不要为了消除这些提示修改云平台 agent 或关闭系统防护。

## 测试边界

新增回归包括生成路径、只补缺失配置、备份、原子替换失败保护、活动 master/未决 journal 拒绝及凭据过滤。CI 另在 Ubuntu VM 中使用真实 systemd transient service 与只读 `/var/lib/nginx` 挂载复现旧配置错误，验证新配置通过同一沙箱。测试不会改宿主已有 Nginx 配置或停机。

本次尚未读取目标机 journal，也未在目标服务器执行修复；若重跑仍失败，提供 `deploy/diagnose.py` 输出，而不是清库、放宽权限或不断重复签发证书。
