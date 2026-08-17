# pmail-hermes-push

PMail 邮件服务器插件：新邮件实时推送到 Hermes Agent webhook，由 Hermes 筛选后再转发通知。

利用 PMail 官方的 hook 机制（`ReceiveSaveAfter`，邮件落库后异步触发），把新邮件元信息实时 POST 到 Hermes 的 webhook 地址，实现"服务端收到消息 → Hermes 筛选 → 有价值才通知你"的闭环。

## 工作原理

```
邮件到达 PMail
   │
   ▼
PMail 触发 ReceiveSaveAfter hook（异步）
   │
   ▼
本插件（独立进程，Unix socket 与 PMail 通信）
  │  提取 Subject/From/To/Text(截断)/附件列表/链接(HTML 锚点+纯文本 URL)
  ▼
POST → Hermes webhook（HMAC-SHA256 签名，Generic V2 带时间戳防重放）
   │
   ▼
Hermes agent 按订阅 prompt 筛选 → 转发到 QQ/Telegram 等
```

- 插件是**薄转发器**，不做内容判断，筛选逻辑全部在 Hermes 侧
- 只转发元信息 + 截断正文（默认 5000 字符），**不转发附件本体**
- **自动提取可点击链接**：同时扫 HTML 的 `<a href>` 锚点（带锚文本）和纯文本里的裸 URL，去重后放进 `links` / `links_text` 字段——解决 Discord/Steam 等安全告警邮件"验证链接只在 HTML 里"导致通知里点不了链接的问题
- 进程内按 MessageId 去重，避免重复通知

## 安装

### 1. 获取二进制

方式 A：直接下载 [Release](../../releases) 里的二进制（选你服务器架构）。

方式 B：自己编译（需要 Go 1.24+）：

```bash
git clone https://github.com/jkfujr/pmail-hermes-push.git
cd pmail-hermes-push
go build -o pmail_hermes_push .
# 交叉编译 amd64：GOOS=linux GOARCH=amd64 go build -o pmail_hermes_push .
```

### 2. 安装到 PMail

把二进制放进 PMail 运行目录的 `plugins` 文件夹（和官方插件一样），文件名**不能包含点**：

```bash
cp pmail_hermes_push /path/to/pmail/plugins/
chmod +x /path/to/pmail/plugins/pmail_hermes_push
```

PMail 启动时会自动拉起 plugins 目录下的插件。

### 3. 配置（推荐：UI 配置，实时生效）

PMail 后台 → 插件设置页，找到 pmail-hermes-push，直接填表单保存即可，**无需重启**：

| 配置项 | 说明 |
|---|---|
| Webhook URL | Hermes webhook 完整地址 |
| Webhook Secret | HMAC 密钥，与 webhook 订阅 secret 一致；**留空表示不修改** |
| 通知的收件人 UserID | 逗号分隔；1=管理员。清空=全部用户 |
| 正文最大长度 | 正文截断长度（默认 5000） |
| 事件名 | 默认 receive_save_after |
| 超时 / 重试 | HTTP 超时秒数 / 失败重试次数 |

页面里有「发送测试邮件」按钮，一键验证到 Hermes 的链路。

也可以手写配置文件 `/path/to/pmail/plugins/pmail_hermes_push_config.json`（修改后需重启 PMail 生效）：

```json
{
  "webhookUrl": "http://100.100.0.41:8644/webhooks/pmail-inbox",
  "webhookSecret": "与 Hermes webhook 订阅一致的 secret",
  "notifyUserIds": [1],
  "maxTextLength": 5000,
  "timeoutSec": 10,
  "retryCount": 2,
  "eventType": "receive_save_after"
}
```

| 配置项 | 必填 | 默认 | 说明 |
|---|---|---|---|
| webhookUrl | ✅ | - | Hermes webhook 完整地址 |
| webhookSecret | ✅ | - | HMAC 密钥，必须与 webhook 订阅 secret 一致 |
| notifyUserIds | - | [1] | 通知哪些收件人（UserID，1=管理员）；`[]` 空数组=全部用户 |
| maxTextLength | - | 5000 | 正文截断长度（字符） |
| timeoutSec | - | 10 | HTTP 超时（秒） |
| retryCount | - | 2 | 失败重试次数 |
| eventType | - | receive_save_after | 发送给 Hermes 的事件名，需在订阅 events 列表里 |

> 手写配置文件方式修改后需重启 PMail 生效；UI 方式保存即实时生效。

### 4. Hermes 侧建订阅

```bash
hermes webhook subscribe pmail-inbox \
  --events "receive_save_after" \
  --prompt "新邮件 {subject} 来自 {from.email}：{text} ... 链接：{links_text}" \
  --deliver <qq|telegram> \
  --deliver-chat-id "<你的ID>" \
  --secret "<和插件配置一致的 secret>"
```

> webhook 平台需先启用：`hermes gateway setup` 或手动在 config.yaml 配置 `platforms.webhook`。

## Webhook payload 字段

| 字段 | 说明 |
|---|---|
| event_type | 事件名（默认 receive_save_after） |
| message_id / msg_id | PMail 数据库 ID / RFC Message-ID（用于去重） |
| subject / from / to / date | 邮件头信息 |
| text | 纯文本正文（按 maxTextLength 截断） |
| **links** | 提取到的链接列表 `[{text, url}]`（HTML 锚点 + 纯文本 URL，去重，最多 10 条） |
| **links_text** | links 渲染成的多行文本 `锚文本: url`，prompt 里直接用 `{links_text}` |
| attachments | 附件名/类型/大小（不含本体） |
| recipient_user_ids | 收件人 UserID 列表 |

> 在 prompt 里用 `{links_text}` 或 `{links}` 即可把链接带进通知。验证码/验证链接类邮件务必原样带上 URL，方便在 QQ/Telegram 里直接点。

## 签名格式（Generic V2）

```
X-Webhook-Timestamp: <unix 秒>
X-Webhook-Signature-V2: <hex(HMAC-SHA256(secret, "<timestamp>.<raw_body>"))>
```

带时间戳的 V2 签名有 5 分钟防重放窗口，比裸 body 签名安全。

## 开发

```bash
go mod tidy   # 依赖（PMail 为 monorepo，go.mod 已用 replace 指到 server 子目录）
go build -o pmail_hermes_push .
go test ./...
```

## 参考

- [PMail 仓库](https://github.com/Jinnrry/PMail) — hook 机制见 `server/hooks/`
- [官方微信推送插件](https://github.com/Jinnrry/PMail/tree/master/server/hooks/wechat_push)
- [社区 Telegram 推送插件](https://github.com/ydzydzydz/pmail_telegram_push)

## License

MIT
