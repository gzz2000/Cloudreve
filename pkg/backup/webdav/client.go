package webdav

import (
	"context"
	"crypto/tls"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"path"
	"strings"
	"time"
)

// Client is a minimal WebDAV client for backup uploading.
type Client struct {
	BaseURL         string
	Username        string
	Password        string
	Headers         map[string]string
	InsecureSkipTLS bool
	MaxRetries      int
}

func (c *Client) client() *http.Client {
	tr := &http.Transport{}
	if c.InsecureSkipTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &http.Client{Transport: tr}
}

func (c *Client) buildURL(p string) (string, error) {
	base := strings.TrimRight(c.BaseURL, "/")
	if base == "" {
		return "", fmt.Errorf("invalid base url")
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	return base + path.Clean(p), nil
}

// EnsureDir ensures the remote directory hierarchy exists (MKCOL recursively).
func (c *Client) EnsureDir(ctx context.Context, path string) error {
	// Normalize and walk components, issuing MKCOL where needed.
	cleaned := path
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	parts := strings.Split(strings.Trim(cleaned, "/"), "/")
	prefix := "/"
	cli := c.client()
	for _, part := range parts {
		if part == "" {
			continue
		}
		prefix = pathpkgJoin(prefix, part)
		u, err := c.buildURL(prefix)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, "MKCOL", u, nil)
		if err != nil {
			return err
		}
		if c.Username != "" || c.Password != "" {
			req.SetBasicAuth(c.Username, c.Password)
		}
		for k, v := range c.Headers {
			req.Header.Set(k, v)
		}
		err = c.doWithRetry(ctx, func() error {
			resp, err := cli.Do(req)
			if err != nil {
				return err
			}
			defer resp.Body.Close()
			if resp.StatusCode == 201 || resp.StatusCode == 200 || resp.StatusCode == 301 || resp.StatusCode == 405 || resp.StatusCode == 409 {
				return nil
			}
			return &httpError{StatusCode: resp.StatusCode}
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// Put uploads a file to remote path via HTTP PUT, streaming from reader.
func (c *Client) Put(ctx context.Context, path string, r io.Reader, length int64) error {
	// Do not retry here because the reader is one-shot streaming.
	// Retries should be handled by the caller by recreating the reader.
	u, err := c.buildURL(path)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, u, r)
	if err != nil {
		return err
	}
	if length >= 0 {
		req.ContentLength = length
	}
	if c.Username != "" || c.Password != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}
	for k, v := range c.Headers {
		req.Header.Set(k, v)
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return &httpError{StatusCode: resp.StatusCode}
}

type httpError struct{ StatusCode int }

func (e *httpError) Error() string { return http.StatusText(e.StatusCode) }

// pathpkgJoin joins URL path segments with single slash.
func pathpkgJoin(a, b string) string {
	if strings.HasSuffix(a, "/") {
		return a + b
	}
	return a + "/" + b
}

func (c *Client) doWithRetry(ctx context.Context, fn func() error) error {
	max := c.MaxRetries
	if max <= 0 {
		max = 5
	}
	delay := time.Second
	for attempt := 0; attempt < max; attempt++ {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := fn()
		if err == nil {
			return nil
		}
		// last attempt
		if attempt == max-1 {
			return err
		}
		select {
		case <-time.After(delay):
			if delay < 30*time.Second {
				delay *= 2
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// ListDir lists files under a directory (name -> size) using PROPFIND depth=1.
func (c *Client) ListDir(ctx context.Context, dir string) (map[string]int64, error) {
	u, err := c.buildURL(dir)
	if err != nil {
		return nil, err
	}
	if !strings.HasSuffix(u, "/") {
		u = u + "/"
	}
	var parsed multistatus
	err = c.doWithRetry(ctx, func() error {
		body := `<?xml version="1.0" encoding="utf-8" ?>
<d:propfind xmlns:d="DAV:">
  <d:prop>
    <d:displayname />
    <d:getcontentlength />
  </d:prop>
</d:propfind>`
		req, err := http.NewRequestWithContext(ctx, "PROPFIND", u, strings.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Depth", "1")
		req.Header.Set("Content-Type", "application/xml; charset=utf-8")
		if c.Username != "" || c.Password != "" {
			req.SetBasicAuth(c.Username, c.Password)
		}
		for k, v := range c.Headers {
			req.Header.Set(k, v)
		}
		resp, err := c.client().Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return &httpError{StatusCode: resp.StatusCode}
		}
		dec := xml.NewDecoder(resp.Body)
		if err := dec.Decode(&parsed); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	res := map[string]int64{}
	for _, r := range parsed.Responses {
		name := r.PropStat.Prop.DisplayName
		if name == "" {
			if idx := strings.LastIndex(r.Href, "/"); idx >= 0 && idx < len(r.Href)-1 {
				name = r.Href[idx+1:]
			}
		}
		if name == "" || name == "." || name == ".." {
			continue
		}
		if strings.HasSuffix(r.Href, "/") {
			continue
		}
		res[name] = r.PropStat.Prop.ContentLength
	}
	return res, nil
}

// Minimal XML structs for PROPFIND parsing
type multistatus struct {
 	XMLName   xml.Name   `xml:"multistatus"`
 	Responses []response `xml:"response"`
}

type response struct {
 	Href     string   `xml:"href"`
 	PropStat propstat `xml:"propstat"`
}

type propstat struct {
 	Prop prop `xml:"prop"`
}

type prop struct {
 	DisplayName   string `xml:"displayname"`
 	ContentLength int64  `xml:"getcontentlength"`
}
