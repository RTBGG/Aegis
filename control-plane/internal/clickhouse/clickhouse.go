// Package clickhouse is a tiny dependency-free client for ClickHouse's HTTP
// interface, used for high-volume per-request analytics. It is optional: when no
// URL is configured the client reports Enabled()==false and callers skip it.
package clickhouse

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	base    string
	db      string
	user    string
	pass    string
	http    *http.Client
	enabled bool
}

// New returns a client for the given HTTP endpoint (e.g. http://clickhouse:8123).
// An empty URL yields a disabled client.
func New(rawURL, db, user, pass string) *Client {
	if strings.TrimSpace(rawURL) == "" {
		return &Client{enabled: false}
	}
	return &Client{
		base:    strings.TrimRight(rawURL, "/"),
		db:      db,
		user:    user,
		pass:    pass,
		http:    &http.Client{Timeout: 15 * time.Second},
		enabled: true,
	}
}

func (c *Client) Enabled() bool { return c != nil && c.enabled }

// do POSTs sqlBody to the HTTP interface. params become ClickHouse query
// parameters ({name:Type}); 64-bit ints are returned unquoted for easy decoding.
func (c *Client) do(ctx context.Context, sqlBody string, params map[string]string) ([]byte, error) {
	q := url.Values{}
	if c.db != "" {
		q.Set("database", c.db)
	}
	q.Set("output_format_json_quote_64bit_integers", "0")
	for k, v := range params {
		q.Set("param_"+k, v)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/?"+q.Encode(), strings.NewReader(sqlBody))
	if err != nil {
		return nil, err
	}
	if c.user != "" {
		req.Header.Set("X-ClickHouse-User", c.user)
	}
	if c.pass != "" {
		req.Header.Set("X-ClickHouse-Key", c.pass)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("clickhouse %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

// Exec runs a statement with no result set (DDL, etc.).
func (c *Client) Exec(ctx context.Context, sql string) error {
	_, err := c.do(ctx, sql, nil)
	return err
}

// Insert appends newline-delimited JSON rows to a table via JSONEachRow.
func (c *Client) Insert(ctx context.Context, table, ndjson string) error {
	_, err := c.do(ctx, "INSERT INTO "+table+" FORMAT JSONEachRow\n"+ndjson, nil)
	return err
}

// QueryJSON runs a SELECT and returns the raw ClickHouse JSON body.
func (c *Client) QueryJSON(ctx context.Context, sql string, params map[string]string) ([]byte, error) {
	return c.do(ctx, sql+"\nFORMAT JSON", params)
}

// EnsureSchema creates the analytics table if it does not exist.
func (c *Client) EnsureSchema(ctx context.Context) error {
	return c.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS aegis_requests (
			ts     DateTime,
			host   LowCardinality(String),
			ip     String,
			method LowCardinality(String),
			path   String,
			status UInt16,
			bytes  UInt64,
			ua     String,
			ja4h   String,
			action LowCardinality(String)
		) ENGINE = MergeTree
		PARTITION BY toYYYYMMDD(ts)
		ORDER BY (host, ts)
		TTL ts + INTERVAL 30 DAY`)
}
