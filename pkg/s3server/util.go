package s3server

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	validBucketChar = regexp.MustCompile(`[a-z0-9-]`)
)

// BucketSlug returns a DNS-safe bucket name based on input.
func BucketSlug(in string) string {
	// S3 bucket name: lowercase letters, digits, and hyphens.
	s := strings.ToLower(in)
	var b strings.Builder
	for _, r := range s {
		ch := string(r)
		if validBucketChar.MatchString(ch) {
			b.WriteString(ch)
		} else {
			b.WriteByte('-')
		}
	}
	res := b.String()
	res = strings.Trim(res, "-")
	if res == "" {
		return "bucket"
	}
	return res
}

// awsChunkedReader is a minimal reader that decodes AWS SigV4 streaming payload (aws-chunked).
// It strips the application-level chunk frames and yields the original payload bytes.
type awsChunkedReader struct {
	br   *bufio.Reader
	left int64
	end  bool
	closer io.Closer
}

func newAWSChunkedReader(r io.ReadCloser) io.ReadCloser {
	return &awsChunkedReader{br: bufio.NewReader(r), closer: r}
}

func (a *awsChunkedReader) Read(p []byte) (int, error) {
	if a.end {
		return 0, io.EOF
	}
	// Ensure we have a current chunk size
	if a.left == 0 {
		// Read chunk header line: <hex-size>[;extensions]\r\n
		line, err := a.br.ReadString('\n')
		if err != nil {
			return 0, err
		}
		// Trim CRLF
		line = strings.TrimRight(line, "\r\n")
		// Extract size up to ';' if present
		hexSize := line
		if idx := strings.IndexByte(line, ';'); idx >= 0 {
			hexSize = line[:idx]
		}
		hexSize = strings.TrimSpace(hexSize)
		if hexSize == "" {
			return 0, errors.New("aws-chunked: empty size")
		}
		// Parse hex size (allow uppercase)
		var n int64
		for i := 0; i < len(hexSize); i++ {
			ch := hexSize[i]
			var v byte
			switch {
			case ch >= '0' && ch <= '9':
				v = ch - '0'
			case ch >= 'a' && ch <= 'f':
				v = ch - 'a' + 10
			case ch >= 'A' && ch <= 'F':
				v = ch - 'A' + 10
			default:
				return 0, fmt.Errorf("aws-chunked: invalid hex digit %q", ch)
			}
			n = (n << 4) | int64(v)
		}
		a.left = n
		if a.left == 0 {
			// Consume optional trailer headers until a blank line
			for {
				l, err := a.br.ReadString('\n')
				if err != nil {
					return 0, err
				}
				l = strings.TrimRight(l, "\r\n")
				if l == "" {
					break
				}
			}
			a.end = true
			return 0, io.EOF
		}
	}

	// Read up to a.left bytes into p
	max := int64(len(p))
	if max > a.left {
		max = a.left
	}
	n, err := io.ReadFull(a.br, p[:max])
	if err != nil {
		return n, err
	}
	a.left -= int64(n)
	if a.left == 0 {
		// Discard trailing CRLF for this chunk
		if _, err := a.br.Discard(2); err != nil {
			return n, err
		}
	}
	return n, nil
}

func (a *awsChunkedReader) Close() error {
	return a.closer.Close()
}

// isAWSStreamingPayload reports if the request body is aws-chunked SigV4 streaming.
func isAWSStreamingPayload(headers map[string]string, get func(string) string) bool {
	// x-amz-content-sha256: STREAMING-AWS4-HMAC-SHA256-PAYLOAD or ...-TRAILER
	if v := get("X-Amz-Content-Sha256"); strings.HasPrefix(v, "STREAMING-AWS4-HMAC-SHA256") {
		return true
	}
	// Content-Encoding: aws-chunked
	if strings.EqualFold(get("Content-Encoding"), "aws-chunked") {
		return true
	}
	return false
}

// parseMetaMTime parses a timestamp value from x-amz-meta-mtime.
// Supported formats:
// - Unix seconds (e.g., "1693412345")
// - Unix seconds with fractional part (e.g., "1693412345.123")
// - RFC3339 (e.g., "2023-08-31T12:34:56Z")
// - HTTP time (e.g., time.RFC1123)
// Returns (t, true) if parsed, otherwise (nil, false).
func parseMetaMTime(s string) (*time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, false
	}
	// Try integer Unix seconds first
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		if i < 0 {
			return nil, false
		}
		t := time.Unix(i, 0).UTC()
		return &t, true
	}
	// Try float Unix seconds
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		if f < 0 {
			return nil, false
		}
		sec, frac := math.Modf(f)
		t := time.Unix(int64(sec), int64(frac*1e9)).UTC()
		return &t, true
	}
	// Try RFC3339
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		t = t.UTC()
		return &t, true
	}
	// Try HTTP time formats
	if t, err := http.ParseTime(s); err == nil {
		t = t.UTC()
		return &t, true
	}
	return nil, false
}

// mpuKey returns cache key for multipart session
func mpuKey(id string) string { return "s3mpu_" + id }
