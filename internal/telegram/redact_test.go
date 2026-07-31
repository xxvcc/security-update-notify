package telegram

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestTokenNotLeakedOnNetworkError 守护 H1：传输错误绝不能把 bot token（嵌在 URL 路径里）
// surface 到错误字符串（会被 execute.go 打进 stderr/journal）。
func TestTokenNotLeakedOnNetworkError(t *testing.T) {
	const token = "123456:AA_SECRET_TOKEN_value-xyz"
	c := &Client{
		HTTP:    &http.Client{Timeout: 2 * time.Second},
		BaseURL: "http://127.0.0.1:1", // 连接被拒 -> 传输错误
		Sleep:   func(time.Duration) {},
	}
	err := c.SendMessage(context.Background(), token, "-100999", "hello")
	if err == nil {
		t.Fatal("expected a network error")
	}
	if strings.Contains(err.Error(), token) {
		t.Fatalf("bot token leaked in SendMessage error: %q", err.Error())
	}
	// GetMe 同样不得泄露 token。
	gerr := c.GetMe(context.Background(), token)
	if gerr == nil {
		t.Fatal("expected GetMe to fail against an unreachable host")
	}
	if strings.Contains(gerr.Error(), token) {
		t.Fatalf("bot token leaked in GetMe error: %q", gerr.Error())
	}
}

func TestTokenAndChatIDNotLeakedFromAPIResponse(t *testing.T) {
	const token = "123456:AA_SECRET_TOKEN_value-xyz"
	const chatID = "-100999"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, fmt.Sprintf(`{"ok":false,"description":"request %s for chat %s failed"}`, r.URL.Path, chatID))
	}))
	defer server.Close()
	c := &Client{HTTP: server.Client(), BaseURL: server.URL}

	sendErr := c.SendMessage(context.Background(), token, chatID, "hello")
	if sendErr == nil {
		t.Fatal("expected sendMessage API error")
	}
	if strings.Contains(sendErr.Error(), token) || strings.Contains(sendErr.Error(), chatID) {
		t.Fatalf("Telegram identifier leaked in sendMessage error: %q", sendErr.Error())
	}

	getMeErr := c.GetMe(context.Background(), token)
	if getMeErr == nil {
		t.Fatal("expected getMe API error")
	}
	if strings.Contains(getMeErr.Error(), token) {
		t.Fatalf("Telegram token leaked in getMe error: %q", getMeErr.Error())
	}
}
