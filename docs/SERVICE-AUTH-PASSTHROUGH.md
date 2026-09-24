# ServiceGateway 业务自行鉴权 / 公开透传路由

`service_auth` 用于“这个 path 前缀由业务服务自己决定匿名访问或业务登录”的场景。它与旧 LAN `public` 不同：`public` 仍然不允许在远程模式使用；`service_auth` 是明确为 HTTPS 业务域名设计的远程透传模式。

## 语义

例如路由：

```text
host = avatar.example.com
path = /api/open/
auth = service_auth
```

则 `/api/open/` 下的所有接口都不做 ServiceGateway 身份校验：不要求网关 API Key、不要求客户端证书、不要求 ServiceGateway 微信业务 Token。请求直接到已批准的上游，由上游应用自己的规则决定是否匿名、是否检查自己的 Bearer Token/Cookie、以及具体业务权限。

路径是前缀匹配，必须以 `/` 结尾。`/api/open/` 包含 `/api/open/a`、`/api/open/user/profile` 等，但不包含 `/api/open` 本身。

## 网关仍然执行的保护

`service_auth` 不是关闭网关。仍然保留：

- 远程模式只允许 HTTPS 443、精确业务域名和已批准服务器证书；
- 服务级 `source_cidrs` / 路由更窄的 `allow_cidrs`；
- 每 IP 连接数、请求速率、请求体大小和超时；
- 上游地址必须属于该服务 root grant；
- 清除 `X-Gateway-Key`、ServiceGateway 内部 Secret、伪造的 `X-SG-User-*` / OpenID 等可信身份头；
- 清除 ServiceGateway 管理 Cookie，但保留业务自己的 Cookie；
- 保留客户端 `Authorization`，由业务服务自己的鉴权中间件处理；
- 可选 `upstream_auth.mode=route_secret`，证明请求确实经过该网关路由；
- 访问采样仍不记录 Authorization、Cookie、query/body。

网关会向上游写入：

```text
X-SG-Route: <route-id>
X-SG-Auth: service_auth
```

它们用于路由/审计标识，不是用户身份或秘密凭据。

## 与微信登录路由的区别

- `service_auth`：网关不判断业务用户。适合真正匿名接口，或者业务服务已有自己的 JWT/Cookie/Token。
- `wechat_user`：必须是 ServiceGateway 微信业务用户 Token，网关验证用户、服务作用域和可选角色，并注入可信 User ID/OpenID。
- `api_key`：要求限定路由的网关 Key。
- `mtls`：要求客户端证书。
- `mtls_or_api_key`：证书或 Key 任意一个通过即可。

头像小程序可以同时配置：

```text
/api/public/   -> service_auth
/api/user/     -> wechat_user
/api/admin/    -> wechat_user + business_roles=["admin"]
```

音乐服务也可以配置：

```text
/api/public/   -> service_auth
/api/internal/ -> api_key
```

## 下级路由权限覆盖上级

权限按**最长、最具体的 path 前缀**决定，不从上级路由继承。例如：

```text
/api/          -> service_auth
/api/private/  -> wechat_user
```

则：

- `/api/news`：走 `/api/`，业务自行鉴权；
- `/api/private/profile`：走 `/api/private/`，必须微信登录；
- `/api/private`：不会掉回 `/api/` 公开透传，网关会先在内部归一成 `/api/private/`，再执行下级微信鉴权。

同理，下级可以使用 API Key、mTLS 或其他更严格/不同的模式。**只要存在更具体的下级路由，就完全按下级路由权限执行。**

## 同一域名混合受保护路径

同一 host/443 可以同时存在公开透传和更具体的受保护路径。Nginx 使用最长前缀匹配，所以更具体的路由优先，例如：

```text
/api/          -> service_auth
/api/admin/    -> mtls
```

`/api/admin/users` 会命中 `/api/admin/` 的 mTLS 路由，不会降级到 `/api/` 公开透传。

同一域名如果有 mTLS 路由，TLS server 层必须可选请求客户端证书，再在纯 mTLS location 强制 `$ssl_client_verify == SUCCESS`。这样没有证书的公开/API 请求仍能进入 `service_auth`。浏览器访问同一 hostname 时可能仍看到客户端证书选择提示；如果不希望普通用户遇到证书提示，建议把 mTLS 管理路径放到独立后台域名。

## 发布前检查

远程 `service_auth` 仍要求：

- 业务域名与管理域名分离；
- server certificate 已配置；
- `rate_per_second >= 1`；
- 服务 root grant 的来源 CIDR 确实允许目标用户来源；互联网服务通常需要给该服务单独批准 `0.0.0.0/0`，不要修改全局 CIDR。

发布预览中看到 `service_auth` 时，应把它视为明确的权限放宽：该前缀不再由网关身份层拦截。业务服务必须对本来需要保护的接口自行完成权限校验。
