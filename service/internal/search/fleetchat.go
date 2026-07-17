package search

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// FleetChat calls the confidential-AI fleet's OpenAI-compatible chat
// completion endpoint. It rides the SAME fleet host + attested pin as
// FleetEmbedder (the caller passes the pinned RA-TLS Client), so every
// plaintext-to-fleet flow stays inside Drive's disclosed boundary
// (§8.6). Used for conversation digests and doc summaries (§8.7).
type FleetChat struct {
	BaseURL string
	Model   string
	APIKey  string
	Client  *http.Client
}

// ChatMessage is one OpenAI-style chat message.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// Complete sends messages and returns the assistant's reply text.
// temperature 0 keeps digests reproducible; maxTokens bounds the reply.
func (c *FleetChat) Complete(ctx context.Context, messages []ChatMessage, maxTokens int) (string, error) {
	if c.BaseURL == "" || c.Model == "" {
		return "", fmt.Errorf("fleet chat not configured")
	}
	if maxTokens <= 0 {
		maxTokens = 1024
	}
	body, err := json.Marshal(map[string]any{
		"model":       c.Model,
		"messages":    messages,
		"temperature": 0,
		"max_tokens":  maxTokens,
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(c.BaseURL, "/")+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.APIKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.APIKey)
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 120 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return "", fmt.Errorf("fleet chat: status %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	var out struct {
		Choices []struct {
			Message ChatMessage `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("fleet chat: no choices returned")
	}
	return out.Choices[0].Message.Content, nil
}
