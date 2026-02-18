package virustotal

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client checks hashes via VirusTotal API v3.
type Client struct {
	APIKey     string
	HTTPClient *http.Client
}

func NewClient(apiKey string) *Client {
	return &Client{
		APIKey: apiKey,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// ReportResult contains VT file report.
type ReportResult struct {
	Positives int      `json:"positives"`
	Total     int      `json:"total"`
	Found     bool     `json:"found"`
	Permalink string   `json:"permalink"`
	Scans     map[string]struct {
		Detected bool   `json:"detected"`
		Result   string `json:"result"`
	} `json:"scans,omitempty"`
}

// CheckHash queries VT for file report. Returns positives count, total, error.
// If hash not found or API error, returns 0,0 and error.
func (c *Client) CheckHash(ctx context.Context, hash string) (positives, total int, err error) {
	if c.APIKey == "" {
		return 0, 0, fmt.Errorf("vt api key empty")
	}
	hash = strings.TrimSpace(strings.ToLower(hash))
	if len(hash) != 64 && len(hash) != 40 {
		return 0, 0, fmt.Errorf("invalid hash length")
	}

	u := "https://www.virustotal.com/vtapi/v2/file/report"
	req, err := http.NewRequestWithContext(ctx, "POST", u, strings.NewReader(url.Values{
		"apikey":   {c.APIKey},
		"resource": {hash},
	}.Encode()))
	if err != nil {
		return 0, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.HTTPClient.Do(req)
	if err != nil {
		return 0, 0, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var r ReportResult
	if err := json.Unmarshal(body, &r); err != nil {
		return 0, 0, err
	}
	// VT returns response_code 0 when not found
	if r.Total == 0 && r.Positives == 0 {
		return 0, 0, nil
	}
	return r.Positives, r.Total, nil
}
