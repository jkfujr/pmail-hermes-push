package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Jinnrry/pmail/dto/parsemail"
)

// TestSignV2KnownVector 用固定向量验证签名格式：hex(HMAC-SHA256(secret, "<ts>.<body>"))
func TestSignV2KnownVector(t *testing.T) {
	body := []byte(`{"event_type":"receive_save_after","subject":"hello"}`)
	secret := "test-secret-123"
	ts := int64(1755000000)

	sig := signV2(body, secret, ts)
	if len(sig) != 64 {
		t.Fatalf("signature length = %d, want 64 (sha256 hex)", len(sig))
	}

	// 独立重算验证
	expected := hmacSHA256Hex(secret, strconv.FormatInt(ts, 10)+"."+string(body))
	if sig != expected {
		t.Fatalf("signature mismatch:\n got  %s\n want %s", sig, expected)
	}

	// 跨语言金标准：由 Hermes 端 Python 校验逻辑（webhook.py V2 分支）独立计算
	const pythonGolden = "71fe372d7084479215fcb9416209b0c8fab5b2800b3bea21bd616a85d0a30907"
	if sig != pythonGolden {
		t.Fatalf("cross-language signature mismatch:\n go     %s\n python %s", sig, pythonGolden)
	}
}

// TestPostWebhook 端到端：mock Hermes 端（按 webhook.py 的 V2 校验逻辑），验证插件请求头正确
func TestPostWebhook(t *testing.T) {
	secret := "webhook-secret-abc"
	received := make(chan string, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := make([]byte, r.ContentLength)
		r.Body.Read(body)

		// 模拟 Hermes gateway/platforms/webhook.py 的 V2 校验
		ts := r.Header.Get("X-Webhook-Timestamp")
		sig := r.Header.Get("X-Webhook-Signature-V2")
		expected := hmacSHA256Hex(secret, ts+"."+string(body))
		if sig != expected {
			w.WriteHeader(http.StatusUnauthorized)
			received <- "401"
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(http.StatusBadRequest)
			received <- "400"
			return
		}
		w.WriteHeader(http.StatusOK)
		received <- string(body)
	}))
	defer server.Close()

	hook := &HermesPushHook{
		cfg: PluginConfig{
			WebhookURL: server.URL,
			WebhookSecret: secret,
			TimeoutSec: 5,
			RetryCount: 0,
		},
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"event_type": "receive_save_after",
		"message_id": 42,
		"subject":    "Test mail",
	})
	hook.post(payload)

	select {
	case res := <-received:
		if res == "401" || res == "400" {
			t.Fatalf("mock hermes rejected request: %s", res)
		}
		var got map[string]interface{}
		if err := json.Unmarshal([]byte(res), &got); err != nil {
			t.Fatalf("bad payload echoed: %v", err)
		}
		if got["message_id"] != float64(42) {
			t.Fatalf("message_id not echoed: %v", got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for webhook POST")
	}
}

// TestTruncate 中文截断按 rune 处理，不产生乱码
func TestTruncate(t *testing.T) {
	s := "你好世界，这是一封测试邮件。" + strings.Repeat("x", 100)
	got := truncate(s, 10)
	if !bytes.Contains([]byte(got), []byte("...[truncated]")) {
		t.Fatalf("truncate marker missing: %q", got)
	}
	if len([]rune(got)) > 30 {
		t.Fatalf("truncate too long: %d runes", len([]rune(got)))
	}
}

// TestSettingsHtmlRoutes UI 路由：getSetting 脱敏 / updateSetting 热更新 / testMessage 校验
func TestSettingsHtmlRoutes(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "cfg.json")
	hook := &HermesPushHook{
		cfg: PluginConfig{
			WebhookURL:    "http://hermes:8644/webhooks/pmail-inbox",
			WebhookSecret: "super-secret-value-123456",
			NotifyUserIds: []int{1},
			MaxTextLength: defaultMaxTextLength,
			TimeoutSec:    defaultTimeoutSec,
			RetryCount:    defaultRetryCount,
			EventType:     defaultEventType,
		},
		cfgPath: cfgPath,
		done:    map[int64]time.Time{},
	}

	// 默认返回 HTML 页面
	html := hook.SettingsHtml(nil, "/api/plugin/settings/pmail_hermes_push", "")
	if !strings.Contains(html, "pmail-hermes-push") || !strings.Contains(html, "webhookUrl") {
		t.Fatalf("default settings page missing content")
	}

	// getSetting：secret 脱敏
	resp := hook.SettingsHtml(nil, "getSetting", "")
	var r struct {
		Code int `json:"code"`
		Data PluginConfig
	}
	if err := json.Unmarshal([]byte(resp), &r); err != nil || r.Code != 0 {
		t.Fatalf("getSetting failed: %v %s", err, resp)
	}
	if r.Data.WebhookSecret != "supe****3456" {
		t.Fatalf("secret not masked: %q", r.Data.WebhookSecret)
	}

	// updateSetting：修改并持久化
	update := `{"webhookUrl":"http://new:8644/webhooks/pmail-inbox","webhookSecret":"","notifyUserIds":[1,2],"maxTextLength":3000,"eventType":"receive_save_after"}`
	resp = hook.SettingsHtml(nil, "updateSetting", update)
	if !strings.Contains(resp, `"code":0`) {
		t.Fatalf("updateSetting failed: %s", resp)
	}
	// 新值生效（secret 未改保持旧值）
	cur := hook.currentConfig()
	if cur.WebhookURL != "http://new:8644/webhooks/pmail-inbox" || cur.WebhookSecret != "super-secret-value-123456" {
		t.Fatalf("update not applied: %+v", cur)
	}
	if len(cur.NotifyUserIds) != 2 || cur.MaxTextLength != 3000 {
		t.Fatalf("update fields wrong: %+v", cur)
	}
	// 文件已持久化
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("config not persisted: %v", err)
	}
	// 重载后仍为新值
	reloaded := mergeConfig(defaultConfig(), mustReadConfig(t, cfgPath))
	if reloaded.WebhookURL != "http://new:8644/webhooks/pmail-inbox" {
		t.Fatalf("reload mismatch: %+v", reloaded)
	}

	// updateSetting：secret 提交脱敏占位（含 *）也不修改
	resp = hook.SettingsHtml(nil, "updateSetting", `{"webhookUrl":"http://new:8644/","webhookSecret":"supe****2345"}`)
	if hook.currentConfig().WebhookSecret != "super-secret-value-123456" {
		t.Fatalf("masked secret should not overwrite")
	}

	// testMessage：未配置 URL 时报错
	hook2 := &HermesPushHook{cfg: PluginConfig{}, cfgPath: filepath.Join(t.TempDir(), "c.json"), done: map[int64]time.Time{}}
	resp = hook2.SettingsHtml(nil, "testMessage", "")
	if !strings.Contains(resp, `"code":-1`) {
		t.Fatalf("testMessage should fail without URL: %s", resp)
	}
}

// mustReadConfig 读取配置文件并解析
func mustReadConfig(t *testing.T, path string) PluginConfig {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var c PluginConfig
	if err := json.Unmarshal(data, &c); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestMaskSecret 脱敏规则
func TestMaskSecret(t *testing.T) {
	if maskSecret("abcd") != "****" {
		t.Fatalf("short secret mask wrong")
	}
	if maskSecret("1234567890abcdef") != "1234****cdef" {
		t.Fatalf("mask wrong: %s", maskSecret("1234567890abcdef"))
	}
}

// TestExtractLinks HTML 锚点 + 纯文本 URL 提取、去重、过滤
func TestExtractLinks(t *testing.T) {
	email := &parsemail.Email{
		HTML: []byte(`<html><body>
			<p>New login detected.</p>
			<a href="https://discord.com/verify?token=abc123" style="x">Verify Login</a>
			<a href="mailto:help@discord.com">Mail us</a>
			<a href="/relative/path">relative</a>
			<a href="https://discord.com/verify?token=abc123"><b>dup</b> anchor</a>
			<a href="https://example.com/foo&amp;bar">escaped &amp; link</a>
		</body></html>`),
		Text: []byte("If this was you, ignore. Otherwise: https://discord.com/reset\nsuffix https://example.com/trail, https://example.com/trail;"),
	}
	links := extractLinks(email)
	if len(links) != 4 {
		t.Fatalf("want 4 unique links, got %d: %+v", len(links), links)
	}
	// 第一条：锚文本保留
	if links[0]["url"] != "https://discord.com/verify?token=abc123" {
		t.Fatalf("first url wrong: %+v", links[0])
	}
	if links[0]["text"] != "Verify Login" {
		t.Fatalf("anchor text wrong: %+v", links[0])
	}
	// HTML 实体解码
	hasFoo := false
	for _, l := range links {
		if l["url"] == "https://example.com/foo&bar" {
			hasFoo = true
		}
	}
	if !hasFoo {
		t.Fatalf("html entity url not decoded: %+v", links)
	}
	// mailto / 相对路径被过滤
	for _, l := range links {
		if strings.Contains(l["url"], "mailto") || strings.HasPrefix(l["url"], "/") {
			t.Fatalf("junk link leaked: %+v", l)
		}
	}
}

// TestExtractLinksTextOnly 只有纯文本时也能提取 URL，且去掉尾部标点
func TestExtractLinksTextOnly(t *testing.T) {
	email := &parsemail.Email{
		Text: []byte("点此验证: https://discord.com/verify?token=xyz，若非本人请忽略。"),
	}
	links := extractLinks(email)
	if len(links) != 1 {
		t.Fatalf("want 1 link, got %d: %+v", len(links), links)
	}
	if links[0]["url"] != "https://discord.com/verify?token=xyz" {
		t.Fatalf("url should not include trailing punctuation: %+v", links[0])
	}
	if links[0]["text"] != links[0]["url"] {
		t.Fatalf("text-only link should use url as text: %+v", links[0])
	}
}

// TestLinksText 渲染格式：锚文本: url；无链接返回空串
func TestLinksText(t *testing.T) {
	if linksText(nil) != "" {
		t.Fatalf("nil links should render empty")
	}
	links := []map[string]string{
		{"text": "验证登录", "url": "https://discord.com/verify?token=1"},
		{"text": "https://example.com", "url": "https://example.com"},
	}
	got := linksText(links)
	want := "验证登录: https://discord.com/verify?token=1\nhttps://example.com"
	if got != want {
		t.Fatalf("linksText mismatch:\n got  %q\n want %q", got, want)
	}
}

// TestExtractLinksCap 链接数量上限
func TestExtractLinksCap(t *testing.T) {
	var htmlParts []string
	for i := 0; i < 20; i++ {
		htmlParts = append(htmlParts, `<a href="https://example.com/`+strconv.Itoa(i)+`">link</a>`)
	}
	email := &parsemail.Email{HTML: []byte(strings.Join(htmlParts, " "))}
	links := extractLinks(email)
	if len(links) != maxLinks {
		t.Fatalf("want %d links capped, got %d", maxLinks, len(links))
	}
}

// hmacSHA256Hex 独立实现（模拟 Hermes 端 Python 逻辑的 Go 版本）
func hmacSHA256Hex(secret, data string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}
