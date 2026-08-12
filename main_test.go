package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
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

// hmacSHA256Hex 独立实现（模拟 Hermes 端 Python 逻辑的 Go 版本）
func hmacSHA256Hex(secret, data string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(data))
	return hex.EncodeToString(mac.Sum(nil))
}
