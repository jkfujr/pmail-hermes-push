package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
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
	configPath           = "./plugins/pmail_hermes_push_config.json"
)

//go:embed settings.html
var settingsHTML string

// PluginConfig 插件配置（可通过 PMail 后台 UI 修改，实时生效）
type PluginConfig struct {
	WebhookURL    string `json:"webhookUrl"`              // Hermes webhook 地址
	WebhookSecret string `json:"webhookSecret"`           // HMAC 密钥（与 webhook 订阅 secret 一致）
	NotifyUserIds []int  `json:"notifyUserIds,omitempty"` // 通知的收件人 UserID，空=全部用户
	MaxTextLength int    `json:"maxTextLength,omitempty"` // 正文截断长度
	TimeoutSec    int    `json:"timeoutSec,omitempty"`    // HTTP 超时秒
	RetryCount    int    `json:"retryCount,omitempty"`    // 失败重试次数
	EventType     string `json:"eventType,omitempty"`     // 事件名
}

// apiResponse PMail 插件 UI 标准响应体（与社区插件一致：code 0 成功，-1 失败）
type apiResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func okResp(message string, data interface{}) string {
	b, _ := json.Marshal(apiResponse{Code: 0, Message: message, Data: data})
	return string(b)
}

func errResp(message string) string {
	b, _ := json.Marshal(apiResponse{Code: -1, Message: message})
	return string(b)
}

// HermesPushHook 实现 PMail EmailHook 接口
type HermesPushHook struct {
	cfgMu  sync.Mutex          // 保护 cfg（配置热更新）
	cfg    PluginConfig
	cfgPath string             // 配置文件路径（默认 configPath，测试可覆盖）
	done   map[int64]time.Time // MessageId 去重（进程内，1h 自动清理）
	doneMu sync.Mutex
}

func (h *HermesPushHook) GetName(ctx *context.Context) string {
	return "pmail_hermes_push"
}

func (h *HermesPushHook) currentConfig() PluginConfig {
	h.cfgMu.Lock()
	defer h.cfgMu.Unlock()
	return h.cfg
}

// updateConfig 热更新内存配置并持久化到文件
func (h *HermesPushHook) updateConfig(newCfg PluginConfig) error {
	h.cfgMu.Lock()
	h.cfg = newCfg
	h.cfgMu.Unlock()
	return saveConfigFile(h.cfgPath, newCfg)
}

// SettingsHtml PMail 后台插件页：内嵌 UI + getSetting/updateSetting/testMessage 动作路由
func (h *HermesPushHook) SettingsHtml(ctx *context.Context, url string, requestData string) string {
	switch {
	case strings.Contains(url, "getSetting"):
		return h.getSetting()
	case strings.Contains(url, "updateSetting"):
		return h.updateSetting(requestData)
	case strings.Contains(url, "testMessage"):
		return h.testMessage()
	default:
		return settingsHTML
	}
}

// getSetting 返回当前配置（secret 脱敏显示）
func (h *HermesPushHook) getSetting() string {
	cfg := h.currentConfig()
	out := cfg
	if cfg.WebhookSecret != "" {
		out.WebhookSecret = maskSecret(cfg.WebhookSecret)
	}
	return okResp("获取设置成功", out)
}

// updateSetting 解析前端提交并保存，实时生效
func (h *HermesPushHook) updateSetting(requestData string) string {
	var req PluginConfig
	if err := json.Unmarshal([]byte(requestData), &req); err != nil {
		log.Errorf("pmail-hermes-push: updateSetting parse error: %v", err)
		return errResp("参数解析失败: " + err.Error())
	}

	cur := h.currentConfig()
	// secret 留空或含 *（脱敏占位）表示不修改
	if req.WebhookSecret == "" || strings.Contains(req.WebhookSecret, "*") {
		req.WebhookSecret = cur.WebhookSecret
	}
	// 未填字段回退默认值/旧值
	if req.MaxTextLength <= 0 {
		req.MaxTextLength = defaultMaxTextLength
	}
	if req.TimeoutSec <= 0 {
		req.TimeoutSec = defaultTimeoutSec
	}
	if req.RetryCount < 0 {
		req.RetryCount = defaultRetryCount
	}
	if req.EventType == "" {
		req.EventType = defaultEventType
	}
	if req.WebhookURL == "" {
		req.WebhookURL = cur.WebhookURL
	}

	if err := h.updateConfig(req); err != nil {
		log.Errorf("pmail-hermes-push: save config error: %v", err)
		return errResp("保存配置失败: " + err.Error())
	}
	log.Infof("pmail-hermes-push: config updated via UI (url=%s)", req.WebhookURL)
	return okResp("保存成功，已实时生效", nil)
}

// testMessage 用当前配置发送一条测试事件到 webhook，验证链路
func (h *HermesPushHook) testMessage() string {
	cfg := h.currentConfig()
	if cfg.WebhookURL == "" {
		return errResp("请先配置 Webhook URL")
	}

	payload := map[string]interface{}{
		"event_type": cfg.EventType,
		"message_id": time.Now().Unix(),
		"msg_id":     fmt.Sprintf("test.%d@localhost", time.Now().UnixNano()),
		"subject":    "pmail-hermes-push 测试邮件",
		"from": map[string]string{
			"name":  "pmail-hermes-push",
			"email": "test@pmail.local",
		},
		"to": []map[string]string{},
		"date": time.Now().Format("2006-01-02 15:04:05"),
		"text": "这是一条来自 PMail 插件的测试通知，验证 Hermes webhook 链路是否正常。",
		"attachments": []map[string]interface{}{},
		"size":       0,
		"recipient_user_ids": []int{},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return errResp("构造测试消息失败: " + err.Error())
	}

	status, respBody, err := postWebhook(cfg.WebhookURL, cfg.WebhookSecret, body, cfg.TimeoutSec)
	if err != nil {
		return errResp("发送失败: " + err.Error())
	}
	if status >= 200 && status < 300 {
		return okResp(fmt.Sprintf("HTTP %d，链路正常", status), string(respBody))
	}
	return errResp(fmt.Sprintf("HTTP %d：%s", status, string(respBody)))
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
	h.doneMu.Lock()
	if _, ok := h.done[email.MessageId]; ok {
		h.doneMu.Unlock()
		return
	}
	h.done[email.MessageId] = time.Now()
	for k, v := range h.done {
		if time.Since(v) > time.Hour {
			delete(h.done, k)
		}
	}
	h.doneMu.Unlock()

	cfg := h.currentConfig()

	// 收件人过滤：只通知关心的 UserID（空=全部）
	if len(cfg.NotifyUserIds) > 0 {
		hit := false
		for _, u := range ue {
			for _, uid := range cfg.NotifyUserIds {
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

	payload := buildPayload(email, ue, cfg)
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
		"event_type":         cfg.EventType,
		"message_id":         email.MessageId,
		"msg_id":             email.MsgID,
		"subject":            email.Subject,
		"from":               from,
		"to":                 to,
		"date":               email.Date,
		"text":               truncate(string(email.Text), cfg.MaxTextLength),
		"attachments":        attachments,
		"size":               email.Size,
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

// postWebhook 发送带 V2 签名的 POST，返回状态码、响应体、错误
func postWebhook(url, secret string, body []byte, timeoutSec int) (int, []byte, error) {
	ts := time.Now().Unix()
	sig := signV2(body, secret, ts)

	client := &http.Client{Timeout: time.Duration(timeoutSec) * time.Second}
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Timestamp", strconv.FormatInt(ts, 10))
	req.Header.Set("X-Webhook-Signature-V2", sig)

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody := make([]byte, 0)
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		respBody = append(respBody, buf[:n]...)
		if err != nil {
			break
		}
	}
	return resp.StatusCode, respBody, nil
}

// post 以 Generic V2 签名（防重放）POST 到 Hermes webhook，失败按配置重试。
func (h *HermesPushHook) post(body []byte) {
	cfg := h.currentConfig()
	if cfg.WebhookURL == "" {
		log.Warn("pmail-hermes-push: webhookUrl not configured, skip notify")
		return
	}

	var lastErr error
	for i := 0; i <= cfg.RetryCount; i++ {
		status, _, err := postWebhook(cfg.WebhookURL, cfg.WebhookSecret, body, cfg.TimeoutSec)
		if err != nil {
			lastErr = err
			log.Warnf("pmail-hermes-push: POST error (attempt %d): %v", i+1, err)
			time.Sleep(time.Duration(i+1) * time.Second)
			continue
		}
		if status >= 200 && status < 300 {
			log.Infof("pmail-hermes-push: notified, status=%d", status)
			return
		}
		lastErr = fmt.Errorf("http %d", status)
		if status == 401 || status == 403 {
			log.Errorf("pmail-hermes-push: auth failed (HTTP %d), check webhookSecret", status)
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

// maskSecret 脱敏显示密钥：保留首尾 4 位
func maskSecret(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

// loadConfig 读取配置文件（不存在则返回默认值）
func loadConfig() PluginConfig {
	cfg := defaultConfig()
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Warn("pmail-hermes-push: config file not found, using defaults. 可在 PMail 后台插件页配置")
		return cfg
	}
	var loaded PluginConfig
	if err := json.Unmarshal(data, &loaded); err != nil {
		log.Errorf("pmail-hermes-push: config parse error: %v", err)
		return cfg
	}
	return mergeConfig(cfg, loaded)
}

// defaultConfig 默认配置
func defaultConfig() PluginConfig {
	return PluginConfig{
		NotifyUserIds: []int{1},
		MaxTextLength: defaultMaxTextLength,
		TimeoutSec:    defaultTimeoutSec,
		RetryCount:    defaultRetryCount,
		EventType:     defaultEventType,
	}
}

// mergeConfig 用 loaded 覆盖默认值（零值字段保留默认）
func mergeConfig(def, loaded PluginConfig) PluginConfig {
	cfg := def
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

// saveConfigFile 持久化配置（0600，含密钥）
func saveConfigFile(path string, cfg PluginConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func main() {
	cfg := loadConfig()
	hook := &HermesPushHook{
		cfg:     cfg,
		cfgPath: configPath,
		done:    map[int64]time.Time{},
	}
	framework.CreatePlugin("pmail_hermes_push", hook).Run()
}
