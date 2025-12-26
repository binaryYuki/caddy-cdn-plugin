package edge

import (
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/google/uuid"
)

func init() {
	caddy.RegisterModule(Edge{})

	httpcaddyfile.RegisterHandlerDirective("edge", func(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
		var m Edge
		if err := m.UnmarshalCaddyfile(h.Dispenser); err != nil {
			return nil, err
		}
		return &m, nil
	})

	httpcaddyfile.RegisterDirectiveOrder("edge", "before", "reverse_proxy")
}

type Edge struct {
	XServer string `json:"x_server,omitempty"`
	Admin   bool   `json:"admin,omitempty"`

	OkCacheSeconds int `json:"ok_cache_seconds,omitempty"`

	Custom404 bool `json:"custom_404,omitempty"`
	Custom502 bool `json:"custom_502,omitempty"`
}

func (Edge) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.edge",
		New: func() caddy.Module { return new(Edge) },
	}
}

func (m *Edge) Provision(ctx caddy.Context) error {
	if m.XServer == "" {
		m.XServer = "Catyuki-CDN"
	}
	if m.OkCacheSeconds <= 0 {
		m.OkCacheSeconds = 86400
	}

	if !m.Custom404 {
		m.Custom404 = true
	}
	if !m.Custom502 {
		m.Custom502 = true
	}
	return nil
}

type upstreamHealth struct {
	Service   string `json:"service"`
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
	Version   string `json:"version"`
}

type healthResponse struct {
	Service      string `json:"service"`
	Status       string `json:"status"`
	Timestamp    string `json:"timestamp"`
	Version      string `json:"version"`
	RequestID    string `json:"requestID"`
	UpstreamCode int    `json:"upstreamCode,omitempty"`
}

type healthRW struct {
	header http.Header
	code   int
	buf    bytes.Buffer
}

func newHealthRW() *healthRW {
	return &healthRW{header: make(http.Header), code: http.StatusOK}
}

func (h *healthRW) Header() http.Header         { return h.header }
func (h *healthRW) WriteHeader(code int)        { h.code = code }
func (h *healthRW) Write(p []byte) (int, error) { return h.buf.Write(p) }

func (m Edge) serveHealth(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	rr := newHealthRW()

	r2 := r.Clone(r.Context())
	r2.Header = r.Header.Clone()
	r2.Header.Set("Accept", "application/json")
	r2.Header.Set("Accept-Encoding", "identity")
	r2.Header.Del("Range")

	if err := next.ServeHTTP(rr, r2); err != nil {
		applyBaseHeaders(w.Header(), m.XServer)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Del("Content-Encoding")
		w.WriteHeader(http.StatusServiceUnavailable)

		out := healthResponse{
			Service:      m.XServer,
			Status:       "error",
			Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
			Version:      "",
			RequestID:    pickTraceID(r),
			UpstreamCode: 0,
		}
		b, _ := json.Marshal(out)
		_, _ = w.Write(b)
		return nil
	}

	raw := rr.buf.Bytes()

	decoded, derr := decodeByContentEncoding(rr.header, raw)
	if derr != nil {
		decoded = raw // decode error, use raw
	}

	var up upstreamHealth
	uerr := json.Unmarshal(decoded, &up)

	out := healthResponse{
		Service:      m.XServer,
		Status:       up.Status,
		Timestamp:    up.Timestamp,
		Version:      up.Version,
		RequestID:    pickTraceID(r),
		UpstreamCode: rr.code,
	}

	// non-2xx or unmarshal error or missing timestamp => error
	if rr.code < 200 || rr.code >= 300 || uerr != nil || out.Status == "" {
		out.Status = "error"
		if out.Timestamp == "" {
			out.Timestamp = time.Now().UTC().Format(time.RFC3339Nano)
		}
	}

	applyBaseHeaders(w.Header(), m.XServer)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Del("ETag")
	w.Header().Del("Content-Length")
	w.Header().Del("Content-Encoding")

	w.WriteHeader(rr.code)

	b, _ := json.Marshal(out)
	_, _ = w.Write(b)
	return nil
}

func decodeByContentEncoding(h http.Header, b []byte) ([]byte, error) {
	enc := strings.ToLower(strings.TrimSpace(h.Get("Content-Encoding")))
	if enc == "" || enc == "identity" {
		return b, nil
	}

	// 多段编码很少见，但还是做个 split
	// e.g. "gzip" or "br" or "zstd"
	parts := strings.Split(enc, ",")
	cur := b
	var err error

	for i := len(parts) - 1; i >= 0; i-- { // 按 RFC 一般是按顺序编码，这里倒序解
		e := strings.TrimSpace(parts[i])
		switch e {
		case "gzip":
			cur, err = gunzip(cur)
		case "br":
			cur, err = decodeBrotli(cur)
		case "zstd":
			cur, err = decodeZstd(cur)
		case "deflate":
			// deflate 很少见，真遇到再补；先显式报错更诚实
			return nil, fmt.Errorf("unsupported content-encoding: deflate")
		default:
			return nil, fmt.Errorf("unsupported content-encoding: %s", e)
		}
		if err != nil {
			return nil, err
		}
	}

	return cur, nil
}

func gunzip(b []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	defer func(zr *gzip.Reader) {
		err := zr.Close()
		if err != nil {
			// ignore
		}
	}(zr)

	return io.ReadAll(zr)
}

func decodeBrotli(b []byte) ([]byte, error) {
	br := brotli.NewReader(bytes.NewReader(b))
	return io.ReadAll(br)
}

func decodeZstd(b []byte) ([]byte, error) {
	dec, err := zstd.NewReader(nil)
	if err != nil {
		return nil, err
	}
	defer dec.Close()
	return dec.DecodeAll(b, nil)
}

func (m *Edge) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "x_server":
				if !d.NextArg() {
					return d.ArgErr()
				}
				m.XServer = d.Val()

			case "admin":
				if !d.NextArg() {
					return d.ArgErr()
				}
				b, err := strconv.ParseBool(d.Val())
				if err != nil {
					return d.ArgErr()
				}
				m.Admin = b

			case "ok_cache_seconds":
				if !d.NextArg() {
					return d.ArgErr()
				}
				n, err := strconv.Atoi(d.Val())
				if err != nil {
					return d.ArgErr()
				}
				m.OkCacheSeconds = n

			case "custom_404":
				if !d.NextArg() {
					return d.ArgErr()
				}
				b, err := strconv.ParseBool(d.Val())
				if err != nil {
					return d.ArgErr()
				}
				m.Custom404 = b

			case "custom_502":
				if !d.NextArg() {
					return d.ArgErr()
				}
				b, err := strconv.ParseBool(d.Val())
				if err != nil {
					return d.ArgErr()
				}
				m.Custom502 = b

			default:
				return d.Errf("unrecognized directive: %s", d.Val())
			}
		}
	}
	return nil
}

func (m Edge) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	if code, ok := getCaddyErrorStatus(r); ok {
		return m.serveErrorPage(w, r, code)
	}

	host := strings.ToLower(strings.TrimSpace(r.Host))
	if host == "cdn.catyuki.com" && r.URL.Path == "/health" {
		return m.serveHealth(w, r, next)
	}

	isLogo := r.URL.Path == "/logo" || r.URL.Path == "/logo.jpg"
	if isLogo {
		r.URL.Path = "/public/logo.jpg"
	}

	rw := &edgeRW{
		ResponseWriter: w,
		req:            r,
		cfg:            m,
		isLogoJPG:      isLogo,
	}
	return next.ServeHTTP(rw, r)
}

func (m Edge) serveErrorPage(w http.ResponseWriter, r *http.Request, code int) error {
	if code == http.StatusNotFound && !m.Custom404 {
		w.WriteHeader(code)
		return nil
	}
	if code >= 500 && !m.Custom502 {
		w.WriteHeader(code)
		return nil
	}
	if code != http.StatusNotFound && code < 500 {
		w.WriteHeader(code)
		return nil
	}

	applyBaseHeaders(w.Header(), m.XServer)

	h := w.Header()
	h.Del("Server")
	h.Del("Via")
	h.Set("Cache-Control", "no-store")
	h.Del("ETag")
	h.Del("Content-Length")

	if wantsHTML(r) {
		h.Set("Content-Type", "text/html; charset=utf-8")
		page := renderPage(r, code)
		w.WriteHeader(code)
		_, _ = w.Write(page)
		return nil
	}

	w.WriteHeader(code)
	_, _ = w.Write([]byte(strconv.Itoa(code)))
	return nil
}

func getCaddyErrorStatus(r *http.Request) (int, bool) {
	v := caddyhttp.GetVar(r.Context(), "http.error.status_code")
	if v == nil {
		return 0, false
	}

	switch x := v.(type) {
	case int:
		return x, true
	case int64:
		return int(x), true
	case float64:
		return int(x), true
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(x))
		if err == nil && n > 0 {
			return n, true
		}
	}
	return 0, false
}

type edgeRW struct {
	http.ResponseWriter
	req *http.Request
	cfg Edge

	wroteHeader bool
	status      int

	isLogoJPG bool
}

func (e *edgeRW) WriteHeader(code int) {
	if e.wroteHeader {
		return
	}
	e.wroteHeader = true
	e.status = code

	e.applyBaseHeaders()

	h := e.Header()
	h.Del("Server")
	h.Del("Via")

	// temp no-cache
	if strings.HasPrefix(e.req.URL.Path, "/temp/") {
		h.Set("Cache-Control", "no-store")
		h.Del("ETag")
		e.ResponseWriter.WriteHeader(code)
		return
	}

	// logo content-type
	if e.isLogoJPG {
		h.Set("Content-Type", "image/jpeg")
	}

	// cache policy
	if e.cfg.Admin {
		h.Set("Cache-Control", "no-store")
	} else {
		if code == http.StatusOK {
			h.Set(
				"Cache-Control",
				"public, max-age=0, s-maxage="+strconv.Itoa(e.cfg.OkCacheSeconds)+", must-revalidate",
			)

			etag := weakETagForBucket(e.cfg.OkCacheSeconds, e.req, "ok")
			h.Set("ETag", etag)

			if ifNoneMatchHit(e.req, etag) {
				h.Del("Content-Type")
				h.Del("Content-Length")
				e.ResponseWriter.WriteHeader(http.StatusNotModified)
				return
			}
		} else {
			h.Set("Cache-Control", "no-cache, must-revalidate")
		}
	}

	if e.cfg.Custom404 && code == http.StatusNotFound {
		e.serveInlineError(code)
		return
	}
	if e.cfg.Custom502 && code >= 500 {
		e.serveInlineError(code)
		return
	}

	e.ResponseWriter.WriteHeader(code)
}

func (e *edgeRW) serveInlineError(code int) {
	h := e.Header()
	h.Set("Cache-Control", "no-store")
	h.Del("ETag")
	h.Del("Content-Length")

	if wantsHTML(e.req) {
		h.Set("Content-Type", "text/html; charset=utf-8")
		page := renderPage(e.req, code)
		e.ResponseWriter.WriteHeader(code)
		_, _ = e.ResponseWriter.Write(page)
		return
	}

	e.ResponseWriter.WriteHeader(code)
}

func (e *edgeRW) Write(p []byte) (int, error) {
	if !e.wroteHeader {
		e.WriteHeader(http.StatusOK)
	}

	if (e.cfg.Custom404 && e.status == http.StatusNotFound) ||
		(e.cfg.Custom502 && e.status >= 500) {
		return len(p), nil
	}

	return e.ResponseWriter.Write(p)
}

func (e *edgeRW) applyBaseHeaders() {
	applyBaseHeaders(e.Header(), e.cfg.XServer)
}

func applyBaseHeaders(h http.Header, xServer string) {
	// Transport & isolation
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Resource-Policy", "same-site")

	// Framing & content sniffing
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")

	// Content security
	h.Set(
		"Content-Security-Policy",
		"default-src 'self'; base-uri 'self'; object-src 'none'; frame-ancestors 'none'; img-src 'self' https://0w338h66nz.ufs.sh data:;",
	)

	// Privacy & permissions
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=(), usb=(), bluetooth=()")

	// Crawlers & meta
	h.Set("X-Robots-Tag", "noindex, nofollow")

	// Identity
	h.Set("X-Server", xServer)
}

func wantsHTML(r *http.Request) bool {
	accept := strings.ToLower(strings.TrimSpace(r.Header.Get("Accept")))
	if accept == "" {
		return false
	}
	if strings.Contains(accept, "text/html") {
		return true
	}
	return false
}

func detectLang(r *http.Request) string {
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("lang")))
	if q == "en" || q == "en-us" || q == "en-gb" {
		return "en"
	}
	if q == "zh" || q == "zh-cn" || q == "zh-hans" {
		return "zh"
	}

	al := strings.ToLower(r.Header.Get("Accept-Language"))
	if strings.Contains(al, "en") {
		return "en"
	}
	return "zh"
}

func pickTraceID(r *http.Request) string {
	if v := strings.TrimSpace(r.Header.Get("Trace-ID")); v != "" {
		return v
	}
	if v := strings.TrimSpace(r.Header.Get("X-Request-ID")); v != "" {
		return v
	}
	return strings.ReplaceAll(uuid.New().String(), "-", "")
}

func weakETagForBucket(okCacheSeconds int, r *http.Request, variant string) string {
	if okCacheSeconds <= 0 {
		okCacheSeconds = 1
	}
	bucket := time.Now().Unix() / int64(okCacheSeconds)
	base := fmt.Sprintf("v=%s|b=%d|p=%s", variant, bucket, r.URL.Path)
	sum := sha1.Sum([]byte(base))
	return `W/"` + hex.EncodeToString(sum[:8]) + `"`
}

func ifNoneMatchHit(r *http.Request, etag string) bool {
	inm := r.Header.Get("If-None-Match")
	if inm == "" {
		return false
	}
	for _, part := range strings.Split(inm, ",") {
		if strings.TrimSpace(part) == etag {
			return true
		}
	}
	return false
}

func htmlEscape(s string) string {
	if s == "" {
		return ""
	}
	var b bytes.Buffer
	b.Grow(len(s) + 16)
	for _, r := range s {
		switch r {
		case '&':
			b.WriteString("&amp;")
		case '<':
			b.WriteString("&lt;")
		case '>':
			b.WriteString("&gt;")
		case '"':
			b.WriteString("&quot;")
		case '\'':
			b.WriteString("&#39;")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

var (
	_ caddy.Provisioner           = (*Edge)(nil)
	_ caddyhttp.MiddlewareHandler = (*Edge)(nil)
	_ caddyfile.Unmarshaler       = (*Edge)(nil)
)
