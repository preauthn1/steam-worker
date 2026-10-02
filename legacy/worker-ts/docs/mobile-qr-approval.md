# 批准官方 Steam 客户端二维码

此功能与 `session.qr` 不同：`session.qr` 是 Worker 发起二维码登录；本页描述 Worker 模拟手机 App 批准另一个官方客户端显示的二维码。

## 前提

- 您自己的 Steam 账户，已经通过 `session.credentials` 选择 `platform=mobile` 并完成 Steam 要求的验证及 `session.poll`。
- 使用 `guard.configure` 配置该账户自己的 `shared_secret`。它是 Steam Guard 密钥，不是账号密码、邮箱验证码或一次性动态码。
- 仅账号密码不足以生成官方扫码批准签名；缺少密钥时服务会拒绝批准，不返回虚构成功。

## 流程

1. 从您自己正在登录的官方 Steam 客户端二维码读取 `https://s.team/q/<version>/<client_id>` 链接。
2. 调用 `session.qr_inspect`，参数 `qr_url`。核对服务器返回的设备、IP/地区和信任信息。
3. 选择 `session.qr_approve` 或 `session.qr_deny`，使用检查返回的短期 `review_handle`。前端同账户会自动填入。
4. 核对写入审核弹窗后明确授权。批准或拒绝均不会自动重试。

不要批准他人发送的二维码；这可能使对方登录您的账户。查询成功不代表请求可信，IP位置也不是完整身份验证。

## 协议

调用认证的 `IAuthenticationService/GetAuthSessionInfo` 查询目标；批准/拒绝使用 `UpdateAuthSessionWithMobileConfirmation`。
签名为 HMAC-SHA256，消息 `version:uint16 LE || client_id:uint64 LE || steam_id:uint64 LE`，密钥为该账户 `shared_secret`。共享密钥和手机平台 access token只在加密账号状态中保存，不作为响应返回。

## 验证边界

协议实现使用官方 Android 静态调用链和公开 protobuf 定义交叉校对。合成响应测试不等同真实扫码批准成功；没有实际账号凭据时不作此声明。不会自动注册、迁移或移除手机验证器。
