package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/Jinnrry/pmail/dto/parsemail"
	"github.com/Jinnrry/pmail/hooks/framework"
	"github.com/Jinnrry/pmail/models"
	"github.com/Jinnrry/pmail/utils/context"
	log "github.com/sirupsen/logrus"
)

const (
	defaultMaxTextLength = 5000 // 正文最大转发长度（rune）
	defaultTimeoutSec    = 10   // HTTP 超时
	defaultRetryCount    = 2    // 失败重试次数
	defaultEventType     = "receive_save_after"
)

// PluginConfig 插件配置，读取 ./plugins/pmail_hermes_push_config.json
type PluginConfig struct {
	WebhookURL    string `json:"webhookUrl"`              // Hermes webhook 地址（必填）
	WebhookSecret string `json:"webhookSecret"`           // HMAC 密钥（必填，与 webhook 订阅 secret 一致）
	NotifyUserIds []int  `json:"notifyUserIds,omitempty"` // 通知的收件人 UserID，默认 [1]（管理员）；空数组=全部用户
	MaxTextLength int    `json:"maxTextLength,omitempty"` // 正文截断长度，默认 5000
	TimeoutSec    int    `json:"timeoutSec,omitempty"`    // HTTP 超时秒，默认 10
	RetryCount    int    `json:"retryCount,omitempty"`    // 失败重试次数，默认 2
	EventType     string `json:"eventType,omitempty"`     // 事件名，默认 receive_save_after
}

// HermesPushHook 实现 PMail EmailHook 接口
type HermesPushHook struct {
	cfg  PluginConfig
	done map[int64]time.Time // MessageId 去重（进程内，1h 自动清理）
	mu   sync.Mutex
}

func (h *HermesPushHook) GetName(ctx *context.Context) string {
	return "pmail_hermes_push"
}

func (h *HermesPushHook) SettingsHtml(ctx *context.Context, url string, requestData string) string {
	return `<div>
<h3>pmail-hermes-push</h3>
<p>New mail &rarr; Hermes webhook.</p>
<p>Config file: <code>plugins/pmail_hermes_push_config.json</code></p>
</div>`
}

func (h *HermesPushHook) SendBefore(ctx *context.Context, email *parsemail.Email) {}

func (h *HermesPushHook) SendAfter(ctx *context.Context, email *parsemail.Email, err map[string]error) {}

func (h *HermesPushHook) ReceiveParseBefore(ctx *context.Context, email *[]byte) {}

func (h *HermesPushHook) ReceiveParseAfter(ctx *context.Context, email *parsemail.Email) {}

// ReceiveSaveAfter 邮件落库后异步触发：筛选 → 组包 → POST 到 Hermes webhook
func (h *HermesPushHook) ReceiveSaveAfter(ctx *context.Context, email *parsemail.Email, ue []*models.UserEmail) {
	if email == nil || email.MessageId <= 0 {
		return
	}

	// 进程内去重：PMail 的异步 hook 在极端情况下可能重复触发
	h.mu.Lock()
	if _, ok := h.done[email.MessageId]; ok {
		h.mu.Unlock()
		return
	}
	h.done[email.MessageId] = time.Now()
	for k, v := range h.done {
		if time.Since(v) > time.Hour {
			delete(h.done, k)
		}
	}
	h.mu.Unlock()

	// 收件人过滤：只通知关心的 UserID（默认管理员 UID=1）
	if len(h.cfg.NotifyUserIds) > 0 {
		hit := false
		for _, u := range ue {
			for _, uid := range h.cfg.NotifyUserIds {
				if u.UserID == uid {
					hit = true
					break
				}
			}
			if hit {
				break
			}
		}
		if !hit {
			log.Debugf("pmail-hermes-push: email %d not for notify users, skip", email.MessageId)
			return
		}
	}

	payload := buildPayload(email, ue, h.cfg)
	body, err := json.Marshal(payload)
	if err != nil {
		log.Errorf("pmail-hermes-push: marshal payload error: %v", err)
		return
	}
	h.post(body)
}

// buildPayload 组装发送给 Hermes 的 JSON。
// 注意：只转发元信息 + 截断正文，不转发附件本体（附件仅列文件名/类型/大小）。
func buildPayload(email *parsemail.Email, ue []*models.UserEmail, cfg PluginConfig) map[string]interface{} {
	from := map[string]string{}
	if email.From != nil {
		from = map[string]string{
			"name":  email.From.Name,
			"email": email.From.EmailAddress,
		}
	}

	to := make([]map[string]string, 0, len(email.To))
	for _, u := range email.To {
		if u == nil {
			continue
		}
		to = append(to, map[string]string{
			"name":  u.Name,
			"email": u.EmailAddress,
		})
	}

	attachments := make([]map[string]interface{}, 0, len(email.Attachments))
	for _, a := range email.Attachments {
		if a == nil {
			continue
		}
		attachments = append(attachments, map[string]interface{}{
			"filename": a.Filename,
			"type":     a.ContentType,
			"size":     len(a.Content),
		})
	}

	userIDs := make([]int, 0, len(ue))
	for _, u := range ue {
		if u != nil {
			userIDs = append(userIDs, u.UserID)
		}
	}

	return map[string]interface{}{
		"event_type":  cfg.EventType,
		"message_id":  email.MessageId,
		"msg_id":      email.MsgID,
		"subject":     email.Subject,
		"from":        from,
		"to":          to,
		"date":        email.Date,
		"text":        truncate(string(email.Text), cfg.MaxTextLength),
		"attachments": attachments,
		"size":        email.Size,
		"recipient_user_ids": userIDs,
	}
}

// signV2 计算 Generic V2 签名：HMAC-SHA256(secret, "<timestamp>.<body>") 的 hex
// 与 Hermes 的 X-Webhook-Signature-V2 校验逻辑一致（见 gateway/platforms/webhook.py）
func signV2(body []byte, secret string, ts int64) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(strconv.FormatInt(ts, 10)))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// post 以 Generic V2 签名（防重放）POST 到 Hermes webhook，失败按配置重试。
func (h *HermesPushHook) post(body []byte) {
	if h.cfg.WebhookURL == "" {
		log.Warn("pmail-hermes-push: webhookUrl not configured, skip notify")
		return
	}
	ts := time.Now().Unix()
	sig := signV2(body, h.cfg.WebhookSecret, ts)

	client := &http.Client{Timeout: time.Duration(h.cfg.TimeoutSec) * time.Second}
	var lastErr error

	for i := 0; i <= h.cfg.RetryCount; i++ {
		req, err := http.NewRequest("POST", h.cfg.WebhookURL, bytes.NewReader(body))
		if err != nil {
			log.Errorf("pmail-hermes-push: new request error: %v", err)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Webhook-Timestamp", strconv.FormatInt(ts, 10))
		req.Header.Set("X-Webhook-Signature-V2", sig)

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			log.Warnf("pmail-hermes-push: POST error (attempt %d): %v", i+1, err)
			time.Sleep(time.Duration(i+1) * time.Second)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			log.Infof("pmail-hermes-push: notified, status=%d", resp.StatusCode)
			return
		}
		lastErr = fmt.Errorf("http %d", resp.StatusCode)
		if resp.StatusCode == 401 || resp.StatusCode == 403 {
			// 签名/权限错误，重试无意义
			log.Errorf("pmail-hermes-push: auth failed (%s), check webhookSecret", resp.Status)
			return
		}
		time.Sleep(time.Duration(i+1) * time.Second)
	}
	log.Errorf("pmail-hermes-push: failed after retries: %v", lastErr)
}

// truncate 按 rune 截断字符串，避免中文乱码
func truncate(s string, max int) string {
	if max <= 0 || len([]rune(s)) <= max {
		return s
	}
	r := []rune(s)
	return string(r[:max]) + "\n...[truncated]"
}

// loadConfig 读取 ./plugins/pmail_hermes_push_config.json（相对 PMail 运行目录）
func loadConfig() PluginConfig {
	cfg := PluginConfig{
		NotifyUserIds: []int{1},
		MaxTextLength: defaultMaxTextLength,
		TimeoutSec:    defaultTimeoutSec,
		RetryCount:    defaultRetryCount,
		EventType:     defaultEventType,
	}

	data, err := os.ReadFile("./plugins/pmail_hermes_push_config.json")
	if err != nil {
		log.Warn("pmail-hermes-push: config file not found, using defaults. Create ./plugins/pmail_hermes_push_config.json")
		return cfg
	}

	var loaded PluginConfig
	if err := json.Unmarshal(data, &loaded); err != nil {
		log.Errorf("pmail-hermes-push: config parse error: %v", err)
		return cfg
	}

	if loaded.WebhookURL != "" {
		cfg.WebhookURL = loaded.WebhookURL
	}
	if loaded.WebhookSecret != "" {
		cfg.WebhookSecret = loaded.WebhookSecret
	}
	if loaded.NotifyUserIds != nil {
		cfg.NotifyUserIds = loaded.NotifyUserIds
	}
	if loaded.MaxTextLength > 0 {
		cfg.MaxTextLength = loaded.MaxTextLength
	}
	if loaded.TimeoutSec > 0 {
		cfg.TimeoutSec = loaded.TimeoutSec
	}
	if loaded.RetryCount >= 0 {
		cfg.RetryCount = loaded.RetryCount
	}
	if loaded.EventType != "" {
		cfg.EventType = loaded.EventType
	}
	return cfg
}

func main() {
	cfg := loadConfig()
	hook := &HermesPushHook{
		cfg:  cfg,
		done: map[int64]time.Time{},
	}
	framework.CreatePlugin("pmail_hermes_push", hook).Run()
}
