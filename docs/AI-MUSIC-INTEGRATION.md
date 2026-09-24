# ServiceGateway × AI 音乐平台接入（评审后落地版）

业务域名：`music.vfuai.com`。本文以现有 AI 音乐评审文档为基础，结合当前 ServiceGateway 的 80/443、mTLS、API Key、root policy 和发布/回滚模型修订。

## 结论

原评审判断基本正确：当前 403 的关键原因不是客户端证书本身，而是业务路由在 `allow_cidrs` 为空时继承全局 `127.0.0.1/32`。**不应为了一个音乐服务把全局 `allowed_cidrs` 改成 `0.0.0.0/0`。**

本版采用以下落地方案：

1. **服务级来源 CIDR 上限**：root policy 中每个已批准服务可选 `source_cidrs`。未设置时继续继承全局值，旧配置行为不变；路由只能等于或收窄所属服务的上限。
2. **边缘鉴权新增“证书或 API Key”模式**：`mtls_or_api_key` 表示客户端证书或限定到该路由的 `X-Gateway-Key` **任意一种验证通过即可**。已短暂合并过的 `mtls_api_key` 值按相同 OR 语义兼容读取，但后台不再生成这个旧名称。
3. **边缘认证与上游身份分离**：路由可配置 `upstream_auth.mode=route_secret`。Nginx 会覆盖客户端伪造头，再向上游注入固定的 `X-SG-Route`、`X-SG-Auth` 和 root-only 的 `X-SG-Upstream-Token`。
4. **API/路由新增时服务只能下拉选择**：只能绑定已经登记的服务，不能在 UI 手填 service ID。
5. **已有路由支持复制**：复制全部非秘密配置并生成新 route id；上游 Secret 永不复制，新路由使用 `route_secret` 时必须单独生成。

## 为什么采用服务级 source_cidrs

ServiceGateway 已经以服务 grant 绑定 unit、健康地址和上游，因此来源网络上限也放在同一 root grant 中最一致：

```json
{
  "services": {
    "ai-music-platform": {
      "units": ["ai-music-platform.service"],
      "upstreams": ["127.0.0.1:18888"],
      "health_url": "http://127.0.0.1:18888/healthz",
      "source_cidrs": ["0.0.0.0/0"]
    }
  }
}
```

未配置 `source_cidrs` 的服务继续使用 `policy.allowed_cidrs`。空的 route `allow_cidrs` 继承所属服务上限；显式 route CIDR 只能收窄，不能扩大。一个服务无法借用另一个服务的来源授权。

本机 root 用 CLI 调整，不让 Web 账号写 root policy：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl service-source-cidrs --service ai-music-platform --cidr 0.0.0.0/0 --confirm-public
```

恢复为继承全局：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl service-source-cidrs --service ai-music-platform --inherit-global
```

这两条命令只改该服务的 root 来源上限，不发布路由、不改其他服务。

## 边缘鉴权模式

远程 443 业务路由现在支持：

- `api_key`：只要求限定到该 route id 的 `X-Gateway-Key`；
- `mtls`：只要求受信客户端证书；
- `mtls_or_api_key`：**证书或 API Key 任意一种通过即可**。

对于音乐后台，可以让浏览器使用客户端证书；外部自动化则使用限定到该 route id 的 API Key。两者不需要同时提供。不要把共享 API Key 硬编码进公开浏览器前端。

组合模式在 TLS server 层使用可选客户端证书：浏览器可提交并验证证书；未提交证书的调用继续进入 HTTP 层，用 API Key 校验。纯 `mtls` 路由仍要求证书成功。若同一 hostname 混合纯 mTLS 与组合模式，server 层保持可选请求证书，纯 mTLS 的 location 再显式拒绝未验证证书。

## 上游身份：route_secret

只依赖 loopback 不能证明请求一定经过 ServiceGateway。因此音乐普通管理 API 在移除应用 Bearer Token 前，应启用：

```json
"upstream_auth": {"mode": "route_secret"}
```

保存路由草稿后，在服务器本机创建并导出该路由 Secret：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl route-secret --route ai-music --output /root/ai-music-gateway.env
```

文件为新建的 root-only `0600` 文件，Secret 不打印到终端、不进入 MySQL、路由 JSON、预览 API 或访问日志。上游应用安全加载 `SG_UPSTREAM_TOKEN` 后校验：

- `X-SG-Upstream-Token` 必须匹配；
- `X-SG-Route` 应为预期 route id；
- `X-SG-Auth` 可用于审计当前边缘认证模式，但不能单独作为秘密。

客户端提交同名头会先被网关清空，再由 Nginx 覆盖。路由被删除并发布后，线上 Nginx 不再注入 Secret；root store 暂时保留记录以避免历史回滚突然失去所需身份材料。

轮换 Secret：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl route-secret --route ai-music --rotate --output /root/ai-music-gateway-next.env
```

先让应用短暂接受旧值和新值，再发布同一快照；每次发布有独立 generation，因此即使路由 JSON digest 未变化，也会重新加载实际 Nginx 配置。发布稳定后再从应用移除旧值。

## AI 音乐平台建议配置

现有路由可继续使用：

- host：`music.vfuai.com`
- upstream：`127.0.0.1:18888`
- server certificate：对应 `music.vfuai.com` 的证书 ID
- client CA：`admin-ca`（若采用 mTLS）
- rate / 并发 / body / timeout：按现有业务值保留
- `upstream_auth.mode=route_secret`

服务来源上限设置成 `0.0.0.0/0` 后，**只有绑定 `ai-music-platform` 的路由可以在该上限内配置来源**；其他服务仍保持原全局上限。

### Worker 权限

`/api/v1/workers/*` 的 Worker Token 保持独立。Gateway route secret 只说明“请求经过该网关路由”，不授予 Worker 权限。若 Worker 接口无需公网，最好不为它创建公网路由；若确实需要公网接入，单独建 route、单独鉴权和限流。

## UI 调整

### 新增 API/路由

“所属服务”只能从当前已登记服务下拉选择，不提供自由文本输入。保存时服务端仍再次验证 service id 存在，不能只依赖浏览器表单。

### 证书 + API Key

鉴权下拉增加：

`客户端证书 或 API Key（任一通过即可）`

选择后要配置 server certificate 与 client CA，以便证书路径可用；需要使用 API Key 的客户端再创建限定到该 route id 的 Key。每次请求只需其中一种身份成功。

### 复制路由

路由列表增加“复制”。复制后：

- 自动生成新的 route id 和“副本”名称；
- 服务、域名、路径、上游、限流、证书、鉴权等配置预填；
- 原路由保持不变；
- 如果 host/path 完全相同，保存时仍按冲突规则拒绝，要求调整；
- `upstream_auth.mode` 在复制时重置为 `none`，因为 Secret 本身绝不能复制。若新 route 也需要上游身份确认，请手工重新选择 `route_secret`，然后为新 route 单独执行 `sgctl route-secret`。
- 如果从 mTLS 路由复制后把边缘鉴权改成 `service_auth`、`wechat_user` 或 `api_key`，后台会自动清空旧 `client_ca`；直接 API 提交残留 `client_ca` 仍会被后端拒绝。
- 发布预览发现某 route 启用了 `route_secret` 但还没有对应 Secret 时，会直接阻止发布并列出 route id；不需要 Secret 的公开路由应把“上游身份确认”设为 `none`。

## 音乐服务迁移顺序

1. 升级 ServiceGateway，但先保留音乐应用现有普通 Bearer Token。
2. 为 `ai-music-platform` 设置服务级 `source_cidrs=["0.0.0.0/0"]`，不改全局 CIDR。
3. 编辑/复制 `ai-music` 路由；根据客户端选择 `mtls` 或 `mtls_or_api_key`，启用 `route_secret`。
4. 创建该 route 的 upstream Secret，并配置到 AI 音乐应用。
5. AI 音乐普通管理 API 同时接受“旧 Bearer Token”与“正确 Gateway route secret”作为短暂迁移期。
6. 发布网关路由并验证：组合模式下，正确证书（不带 Key）可达；不带证书但带正确 Key 也可达；两者都没有时拒绝。纯 mTLS 模式仍必须有正确证书。
7. 验证本机直接访问 `127.0.0.1:18888` 且没有 route secret 时，普通管理 API 返回 401/403。
8. 验证 Worker Token 与 Gateway route secret 权限隔离。
9. 前端移除应用 Bearer Token 输入和本地存储。
10. 最后撤销普通旧 Bearer Token；保留 Worker Token。

## 禁止的临时做法

不要把全局 `policy.allowed_cidrs` 改为 `0.0.0.0/0` 来打通音乐服务。这样会扩大所有继承全局配置的业务路由，且未来新路由漏配时也会扩大网络攻击面。

不要把 Gateway route secret、Worker Token、MiniMax Key 或数据库凭据返回给浏览器。不要把 route secret 当成 Worker 授权。

## 验收

至少验证：

- 音乐服务级 `/0` 不改变其他服务的最终 CIDR；
- `mtls_or_api_key` 使用正确证书但无 Key 时成功，或无证书但正确 Key 时成功；两者都无效时失败；
- API Key 必须限定到正确 route id；
- 客户端伪造 `X-SG-Upstream-Token/X-SG-Route/X-SG-Auth` 会被覆盖；
- 上游收到正确 route secret 后普通 API 成功；本机绕过网关无 secret 时失败；
- Worker Token 与 route secret 互不替代；
- Secret 不出现在预览、访问采样、错误页或管理列表；
- 路由复制不修改原路由、不复用 Secret；
- 保存/预览/发布/回滚和 SSE/WebSocket/大文件行为继续通过现有回归。


### 公开父路由 + 私有子路由

AI 音乐服务可以在同一业务域名按 path 分层：

```text
/api/             -> service_auth
/api/private/     -> wechat_user
/api/internal/    -> api_key
/api/admin/       -> mtls_or_api_key
```

更具体的下级路由优先。`/api/private`（无尾斜杠）也会归一到 `/api/private/` 后执行微信鉴权，不会回落到 `/api/` 透传。
