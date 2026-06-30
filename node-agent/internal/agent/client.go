package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

type bundle struct {
	Version   int64  `json:"version"`
	Checksum  string `json:"checksum"`
	Caddyfile string `json:"caddyfile"`
}

func (c Config) authedClient(timeout time.Duration) *http.Client {
	return &http.Client{Timeout: timeout, Transport: c.transport}
}

// fetchConfig long-polls the control plane for config newer than `since`.
// Returns (bundle, changed, error); changed=false means up to date.
func (c Config) fetchConfig(ctx context.Context, since int64) (*bundle, bool, error) {
	url := c.ControlPlaneURL + "/edge/v1/config?since=" + strconv.FormatInt(since, 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", "Bearer "+c.AgentToken)
	resp, err := c.authedClient(35 * time.Second).Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusNoContent:
		return nil, false, nil
	case http.StatusOK:
		var b bundle
		if err := json.NewDecoder(resp.Body).Decode(&b); err != nil {
			return nil, false, err
		}
		return &b, true, nil
	default:
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		return nil, false, fmt.Errorf("config fetch: %d %s", resp.StatusCode, body)
	}
}

type metricLine struct {
	Domain      string `json:"domain"`
	Requests    int64  `json:"requests"`
	BlockedWAF  int64  `json:"blocked_waf"`
	BlockedRate int64  `json:"blocked_rate"`
	Challenged  int64  `json:"challenged"`
	CacheHits   int64  `json:"cache_hits"`
	CacheMiss   int64  `json:"cache_miss"`
	Bytes       int64  `json:"bytes"`
}

type telemetryPayload struct {
	EdgeName      string       `json:"edge_name"`
	PublicIP      string       `json:"public_ip"`
	AgentVersion  string       `json:"agent_version"`
	Status        string       `json:"status"`
	ConfigVersion int64        `json:"config_version"`
	Metrics       []metricLine `json:"metrics"`
}

func (c Config) sendEvents(ctx context.Context, events []json.RawMessage) error {
	body, err := json.Marshal(map[string]any{"events": events})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ControlPlaneURL+"/edge/v1/events", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.AgentToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.authedClient(15 * time.Second).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("events: %d", resp.StatusCode)
	}
	return nil
}

func (c Config) sendTelemetry(ctx context.Context, p telemetryPayload) error {
	body, err := json.Marshal(p)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.ControlPlaneURL+"/edge/v1/telemetry", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.AgentToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.authedClient(10 * time.Second).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("telemetry: %d", resp.StatusCode)
	}
	return nil
}
