package edge

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	texttemplate "text/template"
)

//go:embed templates/*
var templatesFS embed.FS

var (
	htmlTpl *template.Template
	jsonTpl *texttemplate.Template
)

func init() {
	funcMap := template.FuncMap{
		"jsonEscape": jsonEscape,
	}
	var err error
	htmlTpl, err = template.New("default.html").Funcs(funcMap).ParseFS(templatesFS, "templates/default.html")
	if err != nil {
		panic(fmt.Errorf("failed to parse default.html template: %w", err))
	}

	jsonFuncMap := texttemplate.FuncMap{
		"jsonEscape": jsonEscape,
	}
	jsonTpl, err = texttemplate.New("default.json").Funcs(jsonFuncMap).ParseFS(templatesFS, "templates/default.json")
	if err != nil {
		panic(fmt.Errorf("failed to parse default.json template: %w", err))
	}
}

func jsonEscape(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	s := string(b)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// renderError renders the HTML or JSON error page and applies headers
func renderError(w http.ResponseWriter, r *http.Request, status int, xServer string) []byte {
	traceHeader := "X-Catyuki-Lb-Id"
	traceID := w.Header().Get(traceHeader)
	if traceID == "" {
		traceID = r.Header.Get(traceHeader)
	}
	if traceID == "" {
		traceID = pickTraceID(r)
	}

	lang := detectLang(r)
	i18nData := getI18n(lang, status)
	statusText := http.StatusText(status)
	errDesc := getErrorDescription(lang, status, statusText)
	reqID := findRequestID(r.Header, w.Header())

	edgeID := ""
	for k, vv := range r.Header {
		if strings.EqualFold(k, "X-Catyuki-Edge-Id") && len(vv) > 0 {
			edgeID = vv[0]
			break
		}
	}
	if edgeID == "" {
		for k, vv := range w.Header() {
			if strings.EqualFold(k, "X-Catyuki-Edge-Id") && len(vv) > 0 {
				edgeID = vv[0]
				break
			}
		}
	}

	data := map[string]any{
		"Status":           status,
		"Text":             statusText,
		"TraceID":          traceID,
		"Message":          statusText,
		"Description":      i18nData.Description,
		"ErrorDescription": errDesc,
		"I18n":             i18nData,
		"RequestID":        reqID,
		"EdgeID":           edgeID,
		"Server":           xServer,
		"Host":             r.Host,
		"OriginalURI":      r.URL.RequestURI(),
	}

	var buf bytes.Buffer
	var contentType string
	var err error

	if wantsJSON(r) {
		contentType = "application/json; charset=utf-8"
		err = jsonTpl.Execute(&buf, data)
	} else if wantsHTML(r) {
		contentType = "text/html; charset=utf-8"
		err = htmlTpl.Execute(&buf, data)
	} else {
		contentType = "text/plain; charset=utf-8"
		buf.WriteString(fmt.Sprintf("%d %s (Trace ID: %s)", status, statusText, traceID))
	}

	if err != nil {
		buf.Reset()
		buf.WriteString(fmt.Sprintf("%d %s (Trace ID: %s)", status, statusText, traceID))
		contentType = "text/plain; charset=utf-8"
	}

	// Manipulate headers
	dstHeader := w.Header()

	// Strip cache headers
	dstHeader.Del("Age")
	dstHeader.Del("CDN-Cache-Control")
	dstHeader.Del("Cloudflare-CDN-Cache-Control")
	dstHeader.Del("Surrogate-Control")
	dstHeader.Del("ETag")
	dstHeader.Del("Last-Modified")

	// Set standard cache control headers to prevent caching
	dstHeader.Set("Cache-Control", "no-store, max-age=0")
	dstHeader.Set("Surrogate-Control", "no-store")
	dstHeader.Set("Pragma", "no-cache")
	dstHeader.Set("Expires", "0")

	// Security hardening (expect-ct, x-frame-options etc)
	applyBaseHeaders(dstHeader, xServer)
	dstHeader.Set("Content-Security-Policy", "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")

	// Strip content headers that are no longer valid for the new body
	dstHeader.Del("Content-Length")
	dstHeader.Del("Content-Encoding")
	dstHeader.Del("Content-Range")
	dstHeader.Del("Accept-Ranges")

	// Strip candidate request ID headers to avoid duplicate/inconsistent headers
	deleteHeaderFold := func(h http.Header, name string) {
		var keysToDelete []string
		for k := range h {
			if strings.EqualFold(k, name) {
				keysToDelete = append(keysToDelete, k)
			}
		}
		for _, k := range keysToDelete {
			h.Del(k)
		}
	}
	for _, h := range []string{"requestid", "x-requestid", "x-request-id", "x-req-id", "requestID"} {
		deleteHeaderFold(dstHeader, h)
	}

	// Set/overwrite custom headers
	dstHeader.Set("Content-Type", contentType)
	dstHeader.Set(traceHeader, traceID)
	if reqID != "" {
		dstHeader.Set("X-Catyuki-Req-Id", reqID)
	}

	return buf.Bytes()
}

func findRequestID(reqHeader, respHeader http.Header) string {
	getVal := func(h http.Header, name string) string {
		if val := h.Get(name); val != "" {
			return val
		}
		for k, vv := range h {
			if strings.EqualFold(k, name) && len(vv) > 0 {
				return vv[0]
			}
		}
		return ""
	}

	candidates := []string{"requestid", "x-requestid", "x-request-id", "x-req-id", "requestID"}
	for _, h := range candidates {
		if val := getVal(respHeader, h); val != "" {
			return val
		}
	}
	for _, h := range candidates {
		if val := getVal(reqHeader, h); val != "" {
			return val
		}
	}
	return ""
}

func wantsJSON(r *http.Request) bool {
	accept := strings.ToLower(r.Header.Get("Accept"))
	if strings.Contains(accept, "application/json") {
		return true
	}
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	if strings.Contains(contentType, "application/json") {
		return true
	}
	if strings.HasPrefix(r.URL.Path, "/api/") {
		return true
	}
	return false
}

func wantsHTML(r *http.Request) bool {
	if wantsJSON(r) {
		return false
	}
	accept := strings.ToLower(r.Header.Get("Accept"))
	if strings.Contains(accept, "text/html") {
		return true
	}
	if !strings.Contains(accept, "xml") {
		return true
	}
	return false
}
