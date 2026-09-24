# ServiceGateway 业务用户与微信小程序登录

本模块面向网关后的业务服务（头像小程序、音乐服务等），与 ServiceGateway 管理员账号完全分离。

## 模型

- 业务用户按 `service_id` 隔离；微信身份按 `service_id + appid + openid` 唯一。
- `unionid` 有则记录，但不自动跨服务合并用户。
- 登录后签发 `sgu_...` 不透明 Bearer Token；数据库只保存哈希，默认有效 168 小时（`SG_BUSINESS_SESSION_HOURS` 可调整）。
- `auth=wechat_user` 的路由必须有该服务有效 Token；`business_roles` 为空表示所有启用用户，非空时进一步限制角色。
- 管理员可按服务查看、停用/恢复、修改角色/显示名/备注，并吊销该用户全部 Token。

## 配置微信小程序

服务先完成本机批准与登记，然后由 root 配置 AppID/AppSecret：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl wechat-config --service avatar --appid wx0123456789abcdef
```

AppSecret 隐藏输入，只保存到 root-only `/etc/servicegateway/wechat/<service>.json`；不进入 MySQL、网页、路由快照或日志。停用新的微信登录：

```bash
sudo /srv/e5-apps/servicegateway/current/.venv/bin/sgctl wechat-disable --service avatar
```

## 小程序登录

小程序调用 `wx.login()` 得到一次性 code 后：

```text
POST https://avatar.example.com/_sg/wechat/avatar/login
Content-Type: application/json

{"code":"wx.login 返回的 code"}
```

root Agent 只调用固定的微信 `code2Session` 接口；只返回 appid/openid/unionid，微信 `session_key` 在 Agent 内直接丢弃。

成功后返回 `access_token`、`expires_in` 和当前业务用户信息。业务 API 使用：

```text
Authorization: Bearer sgu_...
```

## 路由权限

后台路由鉴权选择“微信登录用户”。可选填写业务角色，例如 `user,vip`。Nginx 校验 Token、服务范围、用户状态和角色后，覆盖客户端伪造的同名头并向上游注入：

```text
X-SG-User-ID
X-SG-User-Role
X-SG-WeChat-OpenID
X-SG-WeChat-UnionID
X-SG-Route
X-SG-Auth: wechat_user
```

`/_sg/wechat/<service>/login` 是唯一无需业务 Token 的微信换票入口，但仍受该服务 `source_cidrs` 和登录限流保护。`/_sg/wechat/<service>/userinfo` 必须提供有效业务 Token。

## Token → 用户/OpenID

用户本人查询：

```text
GET https://avatar.example.com/_sg/wechat/avatar/userinfo
Authorization: Bearer sgu_...
```

网关后的本机服务如果要主动解析 Token，需要一个只包含该服务“业务用户查询作用域”的 `X-Gateway-Key`：

```text
POST http://127.0.0.1:19092/internal/business-users/introspect
Host: 127.0.0.1
Content-Type: application/json
X-Gateway-Key: sg_...

{"service_id":"avatar","token":"sgu_..."}
```

该接口只接受真实 loopback 连接，并同时校验查询 Key 的 `user_service_ids`、用户 Token 的服务范围、用户启用状态和 Token 有效期。返回用户 ID、角色、OpenID、UnionID（若有）和过期时间。

创建这种 Key 时，在后台“API 密钥”里只填写“可查询业务用户的服务 ID”；它与路由访问作用域、服务注册作用域相互独立。

## 与业务公开透传的关系

如果某个前缀完全交给业务服务自己判断匿名/自有 JWT/Cookie，不需要 ServiceGateway 微信 Token，应使用 `service_auth`，而不是 `wechat_user`。例如：

```text
/api/public/ -> service_auth
/api/user/   -> wechat_user
```

`service_auth` 会保留业务自己的 Authorization/Cookie，但不会注入微信用户身份；详见 [业务自行鉴权 / 公开透传](SERVICE-AUTH-PASSTHROUGH.md)。

## 与上级公开路由的优先级

微信鉴权可以作为公开父路由的更具体下级规则。例如：

```text
/api/          -> service_auth
/api/private/  -> wechat_user
/api/admin/    -> wechat_user + business_roles=["admin"]
```

规则是**最长、最具体的 path 优先**：

- `/api/news` 走业务自行鉴权；
- `/api/private/profile` 必须微信登录；
- `/api/private` 即使没有尾斜杠，也会先内部归一到 `/api/private/`，再执行微信鉴权；
- 不会因为父路由 `/api/` 更宽松就回落成公开访问。

## 安全边界

- 头像服务 Token 不能访问音乐服务的微信路由，也不能跨服务 introspect。
- 停用业务用户会立即吊销其全部业务 Token；恢复后必须重新微信登录。
- AppSecret 不给 Web 进程；由受限 root Agent 使用。
- `session_key` 不保存、不下发。
- OpenID 是身份标识，不是密码。
- 管理域名的 mTLS + 管理员登录、业务 API Key、Worker Token、数据库密码、route secret 与业务用户 Token 互不替代。

## 推荐接入顺序

1. 更新 ServiceGateway 并运行 Alembic 迁移。
2. 配置服务的微信 AppID/AppSecret。
3. 把需要登录的路由改为 `wechat_user`，按需配置 `business_roles`。
4. 发布路由。
5. 小程序接入 `wx.login -> /_sg/wechat/<service>/login`。
6. 客户端保存业务 Token，并以 Bearer 方式访问业务 API。
7. 后端优先使用可信 `X-SG-User-*`；需要主动解析 Token 时使用 loopback introspection + 专用查询 Key。
8. 验证停用用户、吊销 Token、跨服务 Token、过期 Token 和角色不匹配全部失败。


## 路由复制注意事项

复制已有 mTLS 路由再改成 `wechat_user` 时，管理 UI 会自动清空旧的 `client_ca`；它不属于微信鉴权字段。复制路由也不会继承 `route_secret` 要求，新副本默认 `upstream_auth=none`。如果微信业务路由的上游还要校验 `X-SG-Upstream-Token`，需要显式启用并为新 route id 单独生成 Secret。
