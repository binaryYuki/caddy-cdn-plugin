package edge

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestWantsJSON(t *testing.T) {
	tests := []struct {
		name        string
		accept      string
		contentType string
		path        string
		expected    bool
	}{
		{"Standard JSON accept", "application/json", "", "/", true},
		{"JSON accept with q value", "text/html,application/xhtml+xml,application/json;q=0.9", "", "/", true},
		{"Standard HTML accept", "text/html", "", "/", false},
		{"API path wants JSON", "*/*", "", "/api/v1/users", true},
		{"Content-type JSON", "*/*", "application/json", "/foo", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://localhost"+tt.path, nil)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}
			if tt.contentType != "" {
				req.Header.Set("Content-Type", tt.contentType)
			}
			got := wantsJSON(req)
			if got != tt.expected {
				t.Errorf("wantsJSON() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestWantsHTML(t *testing.T) {
	tests := []struct {
		name     string
		accept   string
		expected bool
	}{
		{"Browser standard", "text/html,application/xhtml+xml,application/xml;q=0.9", true}, // contains text/html, should be true!
		{"Accept with xml only", "application/xml", false},                                  // contains xml, no text/html
		{"Accept with application/xhtml+xml", "application/xhtml+xml", false},               // contains xml, no text/html
		{"Accept not containing xml", "text/html,application/json;q=0.9", false},            // wantsJSON is true, so wantsHTML is false
		{"Browser accept without xml", "text/html,image/webp,*/*", true},                    // contains text/html, should be true
		{"Empty Accept", "", true},                                                          // no xml, defaults to true
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}
			got := wantsHTML(req)
			if got != tt.expected {
				t.Errorf("wantsHTML() = %v, want %v for Accept=%q", got, tt.expected, tt.accept)
			}
		})
	}
}

func TestWantsHTML_UserAgents(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		accept    string
		expected  bool
	}{
		{"Browser agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "text/html", true},
		{"curl agent", "curl/7.68.0", "text/html", false},
		{"wget agent", "Wget/1.20.3 (linux-gnu)", "", false},
		{"python agent", "python-requests/2.25.1", "*/*", false},
		{"java agent", "Java/1.8.0_292", "text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2", false},
		{"go-http-client agent", "Go-http-client/1.1", "", false},
		{"axios agent", "Axios/0.21.1", "application/json, text/plain, */*", false},
		{"postman agent", "PostmanRuntime/7.26.8", "*/*", false},
		{"reqwest Rust agent", "reqwest/0.11.4", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
			req.Header.Set("User-Agent", tt.userAgent)
			if tt.accept != "" {
				req.Header.Set("Accept", tt.accept)
			}
			got := wantsHTML(req)
			if got != tt.expected {
				t.Errorf("wantsHTML() = %v, want %v for User-Agent=%q, Accept=%q", got, tt.expected, tt.userAgent, tt.accept)
			}
		})
	}
}

func TestRenderError(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://localhost/not-found", nil)
	req.Header.Set("X-Request-ID", "test-request-id-12345")
	req.Header.Set("X-Catyuki-Lb-Id", "test-trace-id-54321")

	rec := httptest.NewRecorder()
	body := renderError(rec, req, http.StatusNotFound, "Test-Server")

	if rec.Code != http.StatusOK {
		t.Errorf("expected recorder status code to be OK, got %d", rec.Code)
	}

	// Verify headers
	h := rec.Header()
	if got := h.Get("X-Catyuki-Lb-Id"); got != "test-trace-id-54321" {
		t.Errorf("X-Catyuki-Lb-Id = %q, want %q", got, "test-trace-id-54321")
	}
	if got := h.Get("X-Catyuki-Req-Id"); got != "test-request-id-12345" {
		t.Errorf("X-Catyuki-Req-Id = %q, want %q", got, "test-request-id-12345")
	}
	if got := h.Get("Referrer-Policy"); got != "same-origin" {
		t.Errorf("Referrer-Policy = %q, want %q", got, "same-origin")
	}
	if got := h.Get("Expect-CT"); got != "max-age=86400, enforce" {
		t.Errorf("Expect-CT = %q, want %q", got, "max-age=86400, enforce")
	}
	if got := h.Get("X-Frame-Options"); got != "DENY" {
		t.Errorf("X-Frame-Options = %q, want %q", got, "DENY")
	}
	if got := h.Get("Cache-Control"); got != "no-store, max-age=0" {
		t.Errorf("Cache-Control = %q, want %q", got, "no-store, max-age=0")
	}

	// Verify body contains some variables
	bodyStr := string(body)
	if !strings.Contains(bodyStr, "404") {
		t.Errorf("expected body to contain status code 404")
	}
	if !strings.Contains(bodyStr, "test-trace-id-54321") {
		t.Errorf("expected body to contain trace ID")
	}
	if !strings.Contains(bodyStr, "Test-Server") {
		t.Errorf("expected body to contain server name")
	}
}

func TestIPCountryHeaderConversion(t *testing.T) {
	m := &Edge{logger: zap.NewNop()}

	tests := []struct {
		name       string
		inHeader   string
		inValue    string
		unexpected string
	}{
		{"Ali IP Country", "ali-ip-country", "CN", "EO-Client-IPCountry"},
		{"EO Client IP Country", "EO-Client-IPCountry", "US", "ali-ip-country"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
			req.Header.Set(tt.inHeader, tt.inValue)

			rec := httptest.NewRecorder()
			next := testHandler(func(w http.ResponseWriter, r *http.Request) error {
				// Verify normalized header is set on the request forwarded to next handler
				if got := r.Header.Get("X-Catyuki-IP-Country"); got != tt.inValue {
					t.Errorf("request header X-Catyuki-IP-Country = %q, want %q", got, tt.inValue)
				}
				// Verify original header is removed from request
				if got := r.Header.Get(tt.inHeader); got != "" {
					t.Errorf("original request header %s was not deleted, got %q", tt.inHeader, got)
				}
				w.WriteHeader(http.StatusOK)
				return nil
			})

			if err := m.ServeHTTP(rec, req, next); err != nil {
				t.Fatalf("ServeHTTP failed: %v", err)
			}

			// Verify normalized header is set on the response returned to client
			if got := rec.Header().Get("X-Catyuki-IP-Country"); got != tt.inValue {
				t.Errorf("response header X-Catyuki-IP-Country = %q, want %q", got, tt.inValue)
			}
		})
	}
}

func TestRequestIDHeaderConversion(t *testing.T) {
	m := &Edge{logger: zap.NewNop()}

	tests := []struct {
		name       string
		inHeader   string
		inValue    string
	}{
		{"X-Request-ID candidate", "x-request-id", "req-11111"},
		{"X-Req-ID candidate", "x-req-id", "req-22222"},
		{"RequestID candidate", "requestid", "req-33333"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
			req.Header.Set(tt.inHeader, tt.inValue)

			rec := httptest.NewRecorder()
			next := testHandler(func(w http.ResponseWriter, r *http.Request) error {
				// Verify normalized header is set on the request forwarded to next handler
				if got := r.Header.Get("X-Catyuki-Req-Id"); got != tt.inValue {
					t.Errorf("request header X-Catyuki-Req-Id = %q, want %q", got, tt.inValue)
				}
				// Verify original header is removed from request
				if got := r.Header.Get(tt.inHeader); got != "" {
					t.Errorf("original request header %s was not deleted, got %q", tt.inHeader, got)
				}
				// Simulate upstream sending back the original header too
				w.Header().Set(tt.inHeader, tt.inValue)
				w.WriteHeader(http.StatusOK)
				return nil
			})

			if err := m.ServeHTTP(rec, req, next); err != nil {
				t.Fatalf("ServeHTTP failed: %v", err)
			}

			// Verify normalized header is set on the response returned to client
			if got := rec.Header().Get("X-Catyuki-Req-Id"); got != tt.inValue {
				t.Errorf("response header X-Catyuki-Req-Id = %q, want %q", got, tt.inValue)
			}
			// Verify original header is removed from response
			if got := rec.Header().Get(tt.inHeader); got != "" {
				t.Errorf("original response header %s was not deleted, got %q", tt.inHeader, got)
			}
		})
	}
}

func TestServeErrorPage_Codes(t *testing.T) {
	m := &Edge{
		logger:    zap.NewNop(),
		Custom400: true,
		Custom403: true,
		Custom404: true,
		Custom502: true,
	}

	tests := []struct {
		code      int
		shouldCap bool
	}{
		{http.StatusBadRequest, true},   // 400
		{http.StatusForbidden, true},     // 403
		{http.StatusNotFound, true},      // 404
		{http.StatusBadGateway, true},    // 502
		{http.StatusUnauthorized, false}, // 401 (should not be captured)
	}

	for _, tt := range tests {
		t.Run(string(rune(tt.code)), func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "http://localhost/", nil)
			rec := httptest.NewRecorder()

			err := m.serveErrorPage(rec, req, tt.code)
			if err != nil {
				t.Fatalf("serveErrorPage returned error: %v", err)
			}

			bodyStr := rec.Body.String()
			isCap := strings.Contains(bodyStr, "Trace ID") || strings.Contains(bodyStr, "Trace-ID") || strings.Contains(bodyStr, "default-src") || strings.Contains(bodyStr, "ConnectionStatus")
			if isCap != tt.shouldCap {
				t.Errorf("code %d: captured=%v, expected=%v, body=%q", tt.code, isCap, tt.shouldCap, bodyStr)
			}
		})
	}
}
