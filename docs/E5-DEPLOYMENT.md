# E5 资产迁移到远程服务器

当前部署基线是 [REMOTE-SECURITY.md](REMOTE-SECURITY.md)，不是早期局域网明文入口。本文只说明旧 E5 资产如何迁移登记。

## 保留原环境

已有文档记录旧 Manager 内部端口为 `18090`，动态登记目录为 `/etc/e5-business-manager/assets.d/`。这是历史文档基线，需在 E5 本机核实，不代表本次已经远程探测。迁移前备份程序版本、数据、数据库和配置，确认任务状态；不要停用正在运行的 Harness、ComfyUI、视频或音乐任务。

在远程服务器独立部署新网关和业务应用。不要复制整个 `/etc`、sudoers 或旧 root 授权目录，也不要复用旧数据库表作为新系统 schema。

## 导出与重新批准

通过旧 Manager 管理员会话把 `/api/overview` 导出为本机 JSON，使用以下命令筛选 manifest 字段：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl export-e5 --overview-file /安全目录/e5-overview.json
```

命令不执行旧 app.py。缺失 health_url、端口或 unit 的资产会提示并跳过；不能猜测上游端口。导出文件不要包含 Cookie、口令或 Token。

根据远程服务器实际安装情况更新 unit、健康地址和入口。每个业务使用专用非 root 用户，只监听 loopback；应用版本、依赖和持久目录分别安装。随后在远程主机批准：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl approve /安全目录/service-registration.json
```

批准只建立本机授权，不安装、启动或注册业务。远程模式不自动读取旧动态注册表作为可信授权。多上游地址由本机管理员审核 policy.json；不得将网关配置为任意目标代理。

## 导入与切换

在新控制台导入整理后的清单，先预览新增/保持/冲突项。相同登记幂等，冲突不静默覆盖。新 API 使用管理员会话加 CSRF，或限定 service_ids 的注册 Key；不沿用旧 `X-E5-Confirm` 本机免登录例外。

创建端口 443、专用业务域名的根路径路由，按远程规范配置 TLS 与 API Key/mTLS。不要假定所有应用支持子路径代理。验证登录、静态资源、刷新、重定向、上传下载、SSE/WebSocket 和任务持久化后，逐个切换客户端地址。保留旧 E5 入口作为回退源。

## 本机诊断

```bash
sudo journalctl -u servicegateway.service -u servicegateway-agent.service -n 100 --no-pager
```

```bash
sudo journalctl -u servicegateway-edge.service -n 100 --no-pager
```

```bash
sudo bash /srv/e5-apps/servicegateway/current/deploy/verify.sh
```

脚本只做基础验收，不能替代 [ACCEPTANCE.md](ACCEPTANCE.md)。所有现场结果记录版本 SHA、环境和日期；未经真实业务和外部端口验收，不切公网流量、不删除旧环境。
