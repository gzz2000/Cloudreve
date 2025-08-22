package s3server

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
	"strconv"
)

const (
	SigAlgorithm = "AWS4-HMAC-SHA256"
	s3Prefix     = "/s3"
)

type SigV4Params struct {
	AccessKey    string
	Date         string // YYYYMMDDTHHMMSSZ or YYYYMMDD in cred scope
	ShortDate    string // YYYYMMDD
	Region       string
	Service      string
	SignedHeaders []string
	Signature    string
	PayloadHash  string
	Presigned    bool
	Expires      int64 // seconds, presigned only
}

// parseAuthorization parses AWS SigV4 Authorization header.
func ParseAuthorization(hdr string) (*SigV4Params, map[string]string) {
	if !strings.HasPrefix(hdr, SigAlgorithm) {
		return nil, nil
	}
	parts := strings.Split(strings.TrimSpace(strings.TrimPrefix(hdr, SigAlgorithm)), ",")
	vals := make(map[string]string)
	for _, p := range parts {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if len(kv) == 2 {
			vals[kv[0]] = strings.Trim(kv[1], " ")
		}
	}
	cred := strings.TrimSpace(strings.TrimPrefix(vals["Credential"], "="))
	sh := strings.TrimSpace(strings.TrimPrefix(vals["SignedHeaders"], "="))
	sig := strings.TrimSpace(strings.TrimPrefix(vals["Signature"], "="))
	credParts := strings.Split(cred, "/")
	if len(credParts) < 5 {
		return nil, nil
	}
	return &SigV4Params{
		AccessKey:    credParts[0],
		ShortDate:    credParts[1],
		Region:       credParts[2],
		Service:      credParts[3],
		Signature:    sig,
		SignedHeaders: strings.Split(sh, ";"),
	}, vals
}

// parsePresigned parses SigV4 presigned URL parameters.
func ParsePresigned(q url.Values) *SigV4Params {
	if q.Get("X-Amz-Algorithm") != SigAlgorithm {
		return nil
	}
	cred := q.Get("X-Amz-Credential")
	credParts := strings.Split(cred, "/")
	if len(credParts) < 5 {
		return nil
	}
	sh := q.Get("X-Amz-SignedHeaders")
	expires := q.Get("X-Amz-Expires")
	var exp int64
	if expires != "" {
		// ignore parse error (treat as zero)
		v, _ := strconv.ParseInt(expires, 10, 64)
		exp = v
	}
	return &SigV4Params{
		AccessKey:    credParts[0],
		ShortDate:    credParts[1],
		Region:       credParts[2],
		Service:      credParts[3],
		SignedHeaders: strings.Split(sh, ";"),
		Signature:    q.Get("X-Amz-Signature"),
		Date:         q.Get("X-Amz-Date"),
		PayloadHash:  q.Get("X-Amz-Content-Sha256"),
		Presigned:    true,
		Expires:      exp,
	}
}

// canonicalRequest builds the canonical request string and returns it with the canonical signed headers list.
func canonicalRequest(r *http.Request, signedHeaders []string, payloadHash string) (string, string) {
	// Method
	var b strings.Builder
	b.WriteString(r.Method)
	b.WriteByte('\n')
	// Canonical URI (path). Do not strip mount prefix; clients sign the exact path (e.g., /s3)
	b.WriteString(escapePath(r.URL.EscapedPath()))
	b.WriteByte('\n')
	// Canonical query string
	qs := canonicalQueryString(r.URL.Query())
	b.WriteString(qs)
	b.WriteByte('\n')
	// Canonical headers
	lh := lowercaseHeaders(signedHeaders)
	sh := strings.Join(lh, ";")
	for _, h := range lh {
		b.WriteString(h)
		b.WriteByte(':')
		val := r.Header.Get(h)
		if h == "host" {
			val = r.Host
		}
		b.WriteString(canonicalHeaderValue(val))
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	// Signed headers list
	b.WriteString(sh)
	b.WriteByte('\n')
	// Payload hash
	if payloadHash == "" {
		payloadHash = r.Header.Get("X-Amz-Content-Sha256")
	}
	if payloadHash == "" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
		payloadHash = "UNSIGNED-PAYLOAD"
	}
	b.WriteString(payloadHash)
	return b.String(), sh
}

func canonicalQueryString(q url.Values) string {
	// include all query parameters for presigned, otherwise just existing
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		vals := q[k]
		sort.Strings(vals)
		for _, v := range vals {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

func lowercaseHeaders(h []string) []string {
	res := make([]string, len(h))
	for i, v := range h {
		res[i] = strings.ToLower(strings.TrimSpace(v))
	}
	return res
}

func canonicalHeaderValue(v string) string {
	v = strings.TrimSpace(v)
	v = strings.ReplaceAll(v, "\\t", " ")
	v = strings.Join(strings.Fields(v), " ")
	return v
}

func escapePath(p string) string { return p }

// (no canonicalURI; we use the exact request path)

// stringToSign builds the SigV4 string to sign.
func stringToSign(amzDate, scope, canonicalReq string) string {
	h := sha256.Sum256([]byte(canonicalReq))
	return SigAlgorithm + "\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(h[:])
}

func hmacSHA256(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

func signingKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	return kSigning
}

func hexHMAC(key []byte, data string) string {
	res := hmacSHA256(key, data)
	return hex.EncodeToString(res)
}

// verifySigV4 verifies the request against a candidate secret. Returns true if signature matches and not expired.
func VerifySigV4(r *http.Request, p *SigV4Params, secret string, now time.Time) bool {
	if p == nil {
		return false
	}
	// Determine amzDate and payloadHash
	amzDate := r.Header.Get("X-Amz-Date")
	if p.Presigned {
		amzDate = p.Date
		// expiry check
		if p.Expires > 0 {
			// parse time
			t, err := time.Parse("20060102T150405Z", amzDate)
			if err == nil && now.After(t.Add(time.Duration(p.Expires)*time.Second)) {
				return false
			}
		}
	}
	if amzDate == "" {
		amzDate = r.Header.Get("x-amz-date")
	}
	if amzDate == "" {
		return false
	}
	shortDate := p.ShortDate
	if shortDate == "" && len(amzDate) >= 8 {
		shortDate = amzDate[:8]
	}
	region := p.Region
	if region == "" {
		region = "us-east-1"
	}
	service := p.Service
	if service == "" {
		service = "s3"
	}
	// Build canonical request using SignedHeaders
	cr, _ := canonicalRequest(r, p.SignedHeaders, p.PayloadHash)
	scope := shortDate + "/" + region + "/" + service + "/aws4_request"
	sts := stringToSign(amzDate, scope, cr)
	key := signingKey(secret, shortDate, region, service)
	expected := hexHMAC(key, sts)
	return strings.EqualFold(expected, p.Signature)
}
