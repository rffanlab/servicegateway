# 业务用户、微信小程序登录与用户 Token

ServiceGateway 的 **管理账号**（admin/operator/viewer）与这里的 **业务用户** 是两套完全独立的身份体系。业务用户属于某一个已登记服务，例如头像小程序或 AI 音乐服务；微信登录不会获得 ServiceGateway 控制台、服务启停、建库、路由发布或证书下载权限。

当前实现面向 **微信小程序 `wx.login() + code2Session`**。它不是微信公众号网页 OAuth 登录。

## 1. 数据与权限模型

每个业务用户至少包含：

- 网关生成的 `user_id`；
- 所属 `service_id`；
- 业务角色 `role`，默认 `user`；
- enabled 状态；
- 微信 AppID + OpenID，UnionID 仅在微信返回时保存；
- 可选显示名称、头像 URL；
- 管理员备注（只在 ServiceGateway 管理后台可见，不返回给小程序或业务服务）；
- 最近登录时间。

业务 Token 是 ServiceGateway 自己签发的随机不透明 Token，格式为 `sgu_...`。数据库只保存 SHA-256 摘要，不保存 Token 明文。默认有效期 30 天，可通过 `SG_BUSINESS_TOKEN_DAYS` 调整为 1–90 天。

一个 Token **只能代表一个 service 下的一个业务用户**，不能跨服务使用。

## 2. 配置微信小程序

AppSecret 不允许从管理网页提交，也不写 MySQL。由本机 root 配置：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl wechat-config --service avatar-app --appid wx1234567890abcdef
```

命令会隐藏输入 AppSecret。配置文件位于：

```text
/etc/servicegateway/wechat-apps/avatar-app.json
```

目录为 root-only 0700，文件为 0600。

如果部署系统已经把 AppSecret 放在一个 root-only 文件中，可使用：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl wechat-config --service avatar-app --appid wx1234567890abcdef --secret-file /root/avatar-wechat-secret
```

查看是否已配置只返回 AppID，不返回 AppSecret：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl wechat-status --service avatar-app
```

AppSecret 只由受限 root Agent 读取。Agent 固定请求微信 `code2Session` 地址；管理 Web 进程拿不到 AppSecret，也不会拿到或返回微信 `session_key`。

## 3. 配置“微信登录后才能访问”的路由

后台新增路由时选择：

```text
边缘鉴权 = 微信登录 Token
```

对应快照值：

```json
{
  "auth": "wechat",
  "user_roles": []
}
```

这类路由仍然是公网 HTTPS 业务路由，但不是匿名接口，也不需要 API Key 或客户端证书。调用者必须携带业务 Token：

```http
Authorization: Bearer sgu_xxxxxxxxx
```

`user_roles=[]` 表示任意启用且已微信登录的该服务用户都可以访问。

例如管理员接口可以配置：

```json
{
  "auth": "wechat",
  "user_roles": ["admin"]
}
```

普通用户 Token 会得到 403。管理员在“业务用户”页面把该服务用户角色修改为 `admin` 后才能访问。

### 同一个域名可以混合多种路径权限

例如：

```text
/api/public-info/   -> 由其他已批准策略处理
/api/user/          -> 微信登录 Token
/api/admin/         -> 微信登录 Token + user_roles=["admin"]
/ops/               -> 纯 mTLS
/automation/        -> API Key
```

这些路径可以共用同一个业务域名和服务器证书。若某些路径使用 mTLS，同一 vhost 内只允许一套 client CA；Nginx 在 server 层可选请求客户端证书，纯 mTLS location 仍会强制证书成功。

## 4. 小程序登录流程

小程序先调用：

```javascript
wx.login({
  success(res) {
    // res.code 发送给自己的业务域名，不要发送 AppSecret。
  }
})
```

然后：

```http
POST https://avatar.example.com/_sg/wechat/avatar-app/login
Content-Type: application/json

{"code":"wx.login 返回的一次性 code"}
```

ServiceGateway 会：

1. 将 code 交给受限 Agent；
2. Agent 使用 root-only AppID/AppSecret 请求微信 code2Session；
3. 只把 AppID/OpenID/可选 UnionID 返回给控制面，丢弃 session_key；
4. 按 `service_id + appid + openid` 查找或创建业务用户；
5. 签发 ServiceGateway 自己的业务 Token。

返回示例：

```json
{
  "access_token": "sgu_...",
  "token_type": "Bearer",
  "expires_in": 2592000,
  "user": {
    "user_id": "...",
    "service_id": "avatar-app",
    "role": "user",
    "openid": "...",
    "unionid": null
  }
}
```

登录入口只会出现在已经发布了 `auth=wechat` 路由的业务域名上。没有发布对应服务的微信路由时，网关拒绝登录。

## 5. Token 查询当前用户

小程序或客户端可直接访问同一个业务域名：

```http
GET https://avatar.example.com/_sg/wechat/avatar-app/me
Authorization: Bearer sgu_...
```

返回用户 ID、service、role、OpenID、可选 UnionID、显示名称、头像 URL、登录时间和 Token 到期时间；不会返回 AppSecret、session_key、Token 摘要或网关管理员备注。

退出登录：

```http
POST https://avatar.example.com/_sg/wechat/avatar-app/logout
Authorization: Bearer sgu_...
```

只撤销当前 Token。

## 6. 网关后面的业务服务如何拿用户身份

通常 **不需要再调查询接口**。

`auth=wechat` 路由验证 Token 后，Nginx 会先清除客户端伪造的同名头，再向上游注入：

```text
X-SG-User-ID
X-SG-User-Service
X-SG-User-Role
X-SG-OpenID
X-SG-UnionID
X-SG-Route
X-SG-Auth: wechat
```

因此业务应用可以直接信任这些由网关覆盖生成的身份头，前提是应用原始监听地址不能暴露公网。

### 主动 introspection

如果业务服务拿到 Bearer Token 后需要主动查询完整身份，可以调用本机控制面：

```bash
curl -sS -X POST http://127.0.0.1:19092/internal/business-users/introspect -H "Authorization: Bearer $TOKEN" -H "X-SG-Route: avatar-user-api" -H "X-SG-Upstream-Token: $SG_UPSTREAM_TOKEN"
```

该接口：

- 只允许 loopback 调用；
- 要求当前已发布 route id；
- 要求该路由启用 `upstream_auth.mode=route_secret`；
- 校验对应的 route-secret，不能只凭 service_id 自报身份；
- Token 必须属于该路由绑定的同一个服务。

返回示例：

```json
{
  "user_id": "...",
  "service_id": "avatar-app",
  "role": "user",
  "openid": "...",
  "unionid": null,
  "appid": "wx...",
  "display_name": "",
  "avatar_url": "",
  "token_expires_at": "..."
}
```

管理员备注不返回。

## 7. 业务用户管理后台

ServiceGateway 控制台新增 **“业务用户”**：

- 按服务筛选用户；
- 查看 OpenID/UnionID、角色、状态、最近登录；
- 修改业务角色；
- 停用/重新启用用户；
- 设置显示名称、头像 URL、管理员备注；
- 主动撤销该用户全部业务 Token；
- 查看该服务微信 AppID 是否已配置。

停用用户会立即撤销该用户全部业务 Token。

这些业务用户不会出现在 ServiceGateway 管理员账号列表里，也不能登录 ServiceGateway 管理控制台。

## 8. 安全边界

- AppSecret 不进入浏览器、MySQL、路由快照、Nginx 配置、访问日志或错误响应。
- 微信 `session_key` 在 Agent 内即丢弃，不返回给网关 Web 进程、小程序或后端业务。
- code2Session 的目标地址固定，不接受用户指定 URL，也禁用环境 HTTP 代理。
- 业务 Token 明文只在登录响应出现一次；数据库仅保存哈希。
- `auth=wechat` 只认可 ServiceGateway 自己的业务 Token，不把 OpenID 本身当 Token。
- OpenID 按小程序 AppID/服务绑定；UnionID 是可选字段，不应假设一定存在。
- 用户角色由网关管理，不允许客户端自行提交角色。
- 用户身份头由 Nginx 清理后覆盖，客户端无法靠伪造 `X-SG-OpenID` 等头绕过 Token。
- 后端 introspection 同时要求 loopback + active route + route-secret，避免任意本机服务查询其他服务用户。
- 管理域名的 mTLS、管理账号、API Key、服务生命周期和数据库权限完全不与业务用户体系复用。

## 9. 升级与首次使用

已有服务器升级：

```bash
cd ~/servicegateway && git fetch origin && git switch main && git pull --ff-only origin main && sudo bash deploy/install.sh
```

安装器会在切换新版本前执行 Alembic 迁移。迁移新增业务用户、微信身份和业务 Token 表，不改已有管理用户表。

推荐上线顺序：

1. 升级 ServiceGateway；
2. root 配置目标 service 的微信 AppID/AppSecret；
3. 后台新增 `auth=wechat` 路由；
4. 若后端需要 introspection，为该路由启用并配置 route-secret；
5. 发布路由；
6. 小程序接入 `wx.login -> /_sg/wechat/<service>/login`；
7. 用返回的 Bearer Token 调业务 API；
8. 验证普通用户/管理员角色路径；
9. 验证停用用户和撤销 Token 立即生效；
10. 验证业务原始端口仍不能从公网直接访问。

## 10. 暂不自动做的事情

code2Session 本身不提供昵称、头像或手机号，因此网关不会伪造这些资料。后续如业务需要微信手机号授权、用户资料更新或多个小程序 AppID 绑定同一业务账号，应单独设计授权流程，而不是把 session_key 或 AppSecret 发给业务前端。
