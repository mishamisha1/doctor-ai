package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

type Client struct {
	APIKey     string
	Model      string
	HTTPClient *http.Client
}

func NewClient(apiKey, model string) *Client {
	if model == "" {
		model = "gpt-5-nano"
	}
	return &Client{
		APIKey: apiKey,
		Model:  model,
		HTTPClient: &http.Client{
			Timeout: 45 * time.Second,
		},
	}
}

type responseReq struct {
	Model        string `json:"model"`
	Input        string `json:"input"`
	Instructions string `json:"instructions,omitempty"`
	Store        bool   `json:"store,omitempty"`
}

type responseResp struct {
	OutputText string `json:"output_text"` // на некоторых ответах может быть пусто
	Output     []struct {
		Type    string `json:"type"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
	} `json:"output"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error,omitempty"`
}

func (c *Client) Explain(ctx context.Context, summary string) (string, error) {
	if c.APIKey == "" {
		return "", errors.New("openai api key is empty")
	}
	if summary == "" {
		return "", errors.New("summary is empty")
	}

	reqBody := responseReq{
		Model:        c.Model,
		Instructions: "Кратко: вердикт (low/med/high), 2-3 причины, 1 рекомендация. Русский. Минимум токенов.",
		Input:        summary,
		Store:        false,
	}

	b, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.openai.com/v1/responses", bytes.NewReader(b))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("openai http %d: %s", resp.StatusCode, string(raw))
	}

	var rr responseResp
	if err := json.Unmarshal(raw, &rr); err != nil {
		return "", fmt.Errorf("decode openai response: %w; raw=%s", err, string(raw))
	}

	if rr.Error != nil {
		return "", fmt.Errorf("openai error: %s (%s)", rr.Error.Message, rr.Error.Type)
	}

	// 1) если output_text заполнен — используем его
	if rr.OutputText != "" {
		return rr.OutputText, nil
	}

	// 2) иначе собираем текст из output[].content[]
	var out bytes.Buffer
	for _, o := range rr.Output {
		for _, c := range o.Content {
			if c.Type == "output_text" || c.Type == "text" {
				out.WriteString(c.Text)
				out.WriteString("\n")
			}
		}
	}
	txt := out.String()
	if txt == "" {
		txt = string(raw) // fallback, чтобы не потерять ответ
	}
	return txt, nil
}
