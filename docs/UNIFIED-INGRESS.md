# 统一 80/443：管理台和业务共用一个网关

## 最终拓扑

```text
客户端
  ├─ TCP 80  → 已登记域名返回 308 到 HTTPS；未知域名返回 404
  └─ TCP 443 → ServiceGateway edge（唯一监听者）
                ├─ admin.example.com → 管理台：mTLS + 来源白名单 + 密码登录
                ├─ api.example.com   → API 业务：TLS + 路由限定 Key
                └─ app.example.com   → 网页业务：TLS + mTLS

内部：127.0.0.1:19092 管理 API / 127.0.0.1:19093 发布状态
      本机 MySQL / 业务 loopback 端口 / Unix socket Agent
```

80 不接受登录、不代理业务。完整安装器启用 `acme_enabled` 后，只有独立 HTTP-01 随机验证文件可直接读取（含尚未登记路由的域名）；其余请求仍按已登记域名跳转、未知域名 404 处理。现在支持 Let’s Encrypt 自动签发和续期，见 [完整部署](FULL-DEPLOYMENT.md)。API 客户端应直接使用 HTTPS，不能先向 HTTP 发令牌再依赖重定向。

管理台和业务在同一个 edge 配置中生成，不再安装第二个 system Nginx 控制台入口，不使用 19091 或外部 191xx 端口。内部应用仍需要各自监听端口，但无需映射到公网。

## 一次性配置，之后通过控制台管理路由

先阅读 REMOTE-SECURITY.md。安装、数据库、管理员初始化步骤保持不变。代码已合并不等于已部署；安装器不修改 SSH、防火墙、云安全组或现有系统 Nginx。

初始 root policy 的 `ingress_enabled=false`，只有内部组件运行。准备好管理域名、服务器证书、管理客户端 CA/CRL 和独立探测证书后，由本机管理员编辑 `/etc/servicegateway/policy.json`：

```json
{
  "remote_mode": true,
  "ingress_enabled": true,
  "listen_address": "0.0.0.0",
  "listen_ports": [443],
  "management_host": "admin.example.com",
  "management_certificate": "admin",
  "management_client_ca": "admin-ca",
  "management_allow_cidrs": ["127.0.0.1/32", "192.0.2.10/32"],
  "allowed_cidrs": ["127.0.0.1/32", "192.0.2.10/32"],
  "allow_public": false,
  "include_legacy_registry": false,
  "services": {}
}
```

**域名和 `192.0.2.10/32` 是示例，不是可照抄的生产来源。** 保留已有 `services` 授权，不要整体覆盖真实策略。`management_allow_cidrs` 独立于业务 `allowed_cidrs`，业务范围扩大不能顺带扩大管理访问。测试阶段可保持 `listen_address=127.0.0.1`；明确对外提供服务时才改为 `0.0.0.0`。

`SG_PUBLIC_ORIGIN` 必须是同一个管理域名的标准 HTTPS 来源，不包含 8443、19091 等额外端口，不设置 Cookie Domain。证书和 CA 文件安装位置、权限、CRL 与探测证书要求见 REMOTE-SECURITY.md。root CA 签名私钥不能上传网关。

确认 80/443 没有其他进程占用：

```bash
sudo ss -ltnp '( sport = :80 or sport = :443 )'
```

若系统 Nginx、Apache、Caddy 或已有容器占用这些端口，先人工盘点其现有业务和回退方案。安装器不会杀进程、卸载它们或覆盖它们的配置。**只有一个实例可以拥有这两个端口。** 不要把旧系统 Nginx 再套在 edge 前面并继续相信 loopback 来源就是原客户端。

在空网关上首次激活统一入口：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl bootstrap-ingress
```

该命令经本机 Unix socket 交给串行 Agent，只有 UID 0 可以调用，且只允许当前 live 配置为空。它复验策略、证书、`nginx -t`、发布标识、管理 TLS 入口与 80 跳转；失败恢复旧配置。它不会清空已经存在的业务配置。已经发布业务的环境使用控制台正常的预览/发布流程；从旧端口架构升级时先保留原管理入口和私有救援通道，逐项调整草稿到 443 再发布。

首次激活后，访问 `https://管理域名/`，由浏览器选择管理客户端证书，再输入管理员密码。不要打开 `/internal/auth`；它只供网关内部鉴权使用。

## 业务配置

远程路由端口固定为 443。填写业务域名、已批准服务、上游、服务器证书 ID、API Key 或 mTLS 策略即可。保存草稿不会改变流量；预览、发布仍使用原有版本校验、审计和回滚。

不同域名可使用不同服务器证书、不同客户端 CA，并同时监听同一 443。例如管理域名用管理专用 CA，网页业务用另一 CA，模型 API 用 Key；业务证书不能获得管理入口访问权。同一个域名的多条路径必须使用相同服务器证书与客户端 CA，不能按路径切换 TLS 握手身份。

未知 SNI 拒绝握手；HTTP Host 与握手 SNI 不匹配则拒绝请求，避免从一个业务域名跳到另一个域名的认证规则。禁止把业务路由绑定到管理域名。管理虚拟主机由 root policy 固定生成，不是一条可以从业务路由列表误删的记录。

80 的跳转目标使用已登记的固定主机名，不使用任意传入的 Host 构造 Location；未登记域名不代理、不跳转。删除业务路由并发布后，相应的 80 跳转也一同更新。

## 旧版本迁移与运维边界

新安装不创建 `deploy/nginx-console.conf` 或 `nginx-console-tls.conf.example`；这些分离入口模板已从仓库移除。若旧部署已经安装了 `/etc/nginx/conf.d/servicegateway-console.conf` 或独立管理 TLS 站点，**代码更新不会自动删除现场文件**，应先确认新管理入口可用，再由本机管理员归档旧站点并检查监听。不能以仓库中删了模板来推断现场端口已经关闭。

网关只统一 HTTP/HTTPS/WS/SSE 入口，不把 SSH、MySQL 等原始协议变成网页路由。MySQL和内部应用不放行公网；SSH保留经过验证的私有运维或云救援入口。没有替代救援通道前不要封禁当前 SSH 会话。

当前生成 IPv4 监听；检查云安全组和主机防火墙的 IPv6 规则，避免已有 IPv6 服务旁路暴露。未部署 HTTP/3，不需要 UDP 443。配置启用后，在另一台机器上核实只有批准的 Web 端口 TCP 80/443 可达，19092/19093、MySQL、模型和业务端口不可达。

## 验证

自动化集成测试用真实 Nginx、不同服务器证书和两套客户端 CA 验证共享监听、域名分流、无证书/错误 CA 拒绝、SNI/Host 跨域拒绝和 80 跳转。测试隔离使用临时高端口映射生成的标准 80/443 配置，不占用开发机的实际公共端口；正式配置始终是 80/443。

真实目标主机仍要验证 DNS、实际证书信任、端口冲突、来源限制、控制台登录、发布失败恢复和业务长连接。合并 main 不会自动启动生产部署或修改防火墙。

## 官方机制说明

- https://nginx.org/en/docs/http/ngx_http_ssl_module.html ：SNI、客户端证书、CRL、ssl_reject_handshake。
- https://nginx.org/en/docs/http/server_names.html ：虚拟主机选择和不同处理阶段的域名匹配。
