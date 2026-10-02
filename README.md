# Steam 本地 Go 服务

纯 Go 后端，中文控制台，保留 Steam 协议操作、加密账户状态、权限检查、幂等写保护。

部署拓扑：浏览器 → Cloudflare Tunnel → 回环地址上的 Go 服务 → Steam。Tunnel 仅承担入口，Steam 请求从本机出网。

## 功能与限制

接口操作目录是能力清单，不承诺完整 aiosteampy SDK 兼容。支持密码/QR 登录、手机平台会话、库存、钱包、市场/交易/确认及检查后批准官方客户端扫码。

扫码批准需要您自己账户的手机平台会话和 `shared_secret`；账号密码不能直接推导共享密钥。不会自动添加、迁移或移除手机验证器。

真实账号登录、资金操作及扫码批准需独立验收。开发阶段仅合成协议测试和公开只读请求，不把它们冒充真实资金操作成功。

## 网页控制台

网页只做一件事：批准电脑上 Steam 客户端显示的登录二维码。

1. 首次打开：用管理员 API 令牌授权，设置你自己的访问密码（8–128 位）。服务端只保存 PBKDF2-SHA256 哈希（`DATA_DIR/console-password.json`）。
2. 之后用这个密码登录，得到 12 小时有效的内存会话；15 分钟内失败 10 次会暂时锁定；退出或修改密码会让会话立即失效。
   页面不使用 `type=password` 和 `<form>`，浏览器密码管理器不会提示保存访问密码或管理员令牌（Chromium 密码管理器日志验证：无保存提示）。
3. 共享 Steam 登录窗口，页面在本机识别二维码 → 显示登录设备 → 批准。二维码过期会自动跳过并等待新码。也可以粘贴二维码链接或上传截图。

会话接口：`GET/POST /v1/session/password`（设置需管理员 API 令牌）、`POST /v1/session/login`、`POST /v1/session/logout`。其余 HTTP API 不变。

## 安全

- 仅监听 127.0.0.1，配合独立 Tunnel。
- API Token 用 SHA256 哈希配置，Steam/Guard 状态 AES256-GCM 加密。
- 密码不持久化；日志不含请求体、Token、Cookie 或原始敏感异常。
- 写操作需 `X-Confirm-Write: true` 与 `Idempotency-Key`，不确定结果不自动重试。
- 账户状态和意图日志使用持久化事务，重启后保留重放保护。
- API、中文字段和前端写入审核保持原格式。

## 构建与测试

```sh
GOMAXPROCS=2 go build -p=1 ./cmd/steam-server
GOMAXPROCS=2 go test -p=1 ./internal/steam ./internal/server
```

配置与状态不应提交版本库；生产使用专门服务用户、私有配置文件及受限状态目录。Cloudflare Token、Tunnel Token和真实域名均只放私有运维配置。

## 许可证

MIT。协议参考 aiosteampy、node-steam-session；浏览器内置 MIT jsQR 解码器，原许可证保留。
