package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"time"
)

// Client is a minimal Starburst Enterprise BIAC REST client.
type Client struct {
	base     *url.URL
	http     *http.Client
	token    string
	user     string
	pass     string
	maxRetry int
	role     string // optional system role sent as X-Trino-Role
}

type clientConfig struct {
	BaseURL    string
	Token      string
	User, Pass string
	CACertFile string
	AllowHTTP  bool
	Role       string // optional system role, sent as X-Trino-Role
	Timeout    time.Duration
}

func newClient(c clientConfig) (*Client, error) {
	u, err := url.Parse(c.BaseURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("invalid or missing URL %q: pass --url https://host or `export STARBURST_URL=...` in THIS shell", c.BaseURL)
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && c.AllowHTTP) {
		return nil, fmt.Errorf("refusing non-HTTPS url (credentials would be sent in clear); use --allow-http only for local testing")
	}
	if c.Role != "" && !roleRe.MatchString(c.Role) {
		return nil, fmt.Errorf("invalid --role %q (letters, digits, underscore only)", c.Role)
	}
	if c.Token == "" && (c.User == "" || c.Pass == "") {
		return nil, fmt.Errorf("credentials required: set STARBURST_TOKEN or STARBURST_USER + STARBURST_PASSWORD")
	}
	tc := &tls.Config{MinVersion: tls.VersionTLS12}
	if c.CACertFile != "" {
		pem, err := os.ReadFile(c.CACertFile)
		if err != nil {
			return nil, err
		}
		pool, _ := x509.SystemCertPool()
		if pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("no certificates found in %s", c.CACertFile)
		}
		tc.RootCAs = pool
	}
	tr := &http.Transport{TLSClientConfig: tc, MaxIdleConnsPerHost: 32, ForceAttemptHTTP2: true}
	return &Client{
		base: u, role: c.Role, token: c.Token, user: c.User, pass: c.Pass, maxRetry: 4,
		http: &http.Client{Transport: tr, Timeout: c.Timeout,
			// never follow redirects: avoids leaking Authorization to another host
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
	}, nil
}

// get performs a GET with retries on 429/5xx and decodes JSON into out.
func (c *Client) get(ctx context.Context, path string, q url.Values, out any) error {
	u := *c.base
	u.Path = path
	u.RawQuery = q.Encode()
	var lastErr error
	for attempt := 0; attempt <= c.maxRetry; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Duration(1<<attempt) * 250 * time.Millisecond):
			}
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		req.Header.Set("Accept", "application/json")
		if c.role != "" {
			req.Header.Set("X-Trino-Role", "system=ROLE{"+c.role+"}")
		}
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		} else {
			req.SetBasicAuth(c.user, c.pass)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		switch {
		case resp.StatusCode == 200:
			dec := json.NewDecoder(bytes.NewReader(body))
			dec.UseNumber() // keep int64 IDs exact
			return dec.Decode(out)
		case resp.StatusCode == 429 || resp.StatusCode >= 500:
			if s, e := strconv.Atoi(resp.Header.Get("Retry-After")); e == nil && s > 0 && s < 30 {
				time.Sleep(time.Duration(s) * time.Second)
			}
			lastErr = fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
		default:
			return &httpError{Status: resp.StatusCode, Msg: fmt.Sprintf("GET %s: HTTP %d: %s", path, resp.StatusCode, truncate(string(body), 300))}
		}
	}
	return lastErr
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "..."
	}
	return s
}

type httpError struct {
	Status int
	Msg    string
}

func (e *httpError) Error() string { return e.Msg }

// roleRe restricts role names so a value can never inject header content.
var roleRe = regexp.MustCompile(`^[A-Za-z0-9_]{1,128}$`)

// send performs a write (POST/PUT/DELETE). Writes are NOT retried on 5xx (a retry
// could duplicate a create); only 429 is retried, because the request was not processed.
func (c *Client) send(ctx context.Context, method, path string, body, out any) error {
	u := *c.base
	u.Path = path
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return err
		}
	}
	for attempt := 0; ; attempt++ {
		req, _ := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(payload))
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if c.role != "" {
			req.Header.Set("X-Trino-Role", "system=ROLE{"+c.role+"}")
		}
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		} else {
			req.SetBasicAuth(c.user, c.pass)
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return err
		}
		rb, _ := io.ReadAll(io.LimitReader(resp.Body, 16<<20))
		resp.Body.Close()
		switch {
		case resp.StatusCode == 429 && attempt < 4:
			time.Sleep(time.Duration(1<<attempt) * 500 * time.Millisecond)
			continue
		case resp.StatusCode >= 200 && resp.StatusCode < 300:
			if out != nil && len(bytes.TrimSpace(rb)) > 0 {
				dec := json.NewDecoder(bytes.NewReader(rb))
				dec.UseNumber()
				return dec.Decode(out)
			}
			return nil
		default:
			return &httpError{Status: resp.StatusCode, Msg: fmt.Sprintf("%s %s: HTTP %d: %s", method, path, resp.StatusCode, truncate(string(rb), 300))}
		}
	}
}
