package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

type testHandler func(http.ResponseWriter, *http.Request) error

func (f testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) error {
	return f(w, r)
}

func TestIsHealthPath(t *testing.T) {
	if !isHealthPath("/health") {
		t.Fatalf("/health should be recognized as health path")
	}
	if !isHealthPath("/rustfs/console/health") {
		t.Fatalf("/rustfs/console/health should be recognized as health path")
	}
	if isHealthPath("/api/health") {
		t.Fatalf("/api/health should not be recognized as health path")
	}
}

func TestServeHTTPHealthNoCacheHeaders(t *testing.T) {
	m := &Edge{XServer: "test-edge", logger: zap.NewNop()}

	req := httptest.NewRequest(http.MethodGet, "https://cdn.example.com/rustfs/console/health", nil)
	req.RemoteAddr = "127.0.0.1:12345"
	rec := httptest.NewRecorder()

	next := testHandler(func(w http.ResponseWriter, r *http.Request) error {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"service":"upstream","status":"ok","timestamp":"2026-01-01T00:00:00Z","version":"v1"}`))
		return nil
	})

	if err := m.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want %q", got, "no-store")
	}
	if got := rec.Header().Get("Surrogate-Control"); got != "no-store" {
		t.Fatalf("Surrogate-Control = %q, want %q", got, "no-store")
	}
}

func TestServeHTTPHealthRateLimited(t *testing.T) {
	m := &Edge{
		XServer:            "test-edge",
		logger:             zap.NewNop(),
		healthLimiters:     make(map[string]*rate.Limiter),
		healthLimiterRPS:   1,
		healthLimiterBurst: 1,
	}

	req := httptest.NewRequest(http.MethodGet, "https://cdn.example.com/health", nil)
	req.RemoteAddr = "127.0.0.2:54321"
	key := healthRateLimitKey(req)
	m.healthLimiters[key] = rate.NewLimiter(0, 0)

	rec := httptest.NewRecorder()
	called := 0
	next := testHandler(func(w http.ResponseWriter, r *http.Request) error {
		called++
		w.WriteHeader(http.StatusOK)
		return nil
	})

	if err := m.ServeHTTP(rec, req, next); err != nil {
		t.Fatalf("ServeHTTP returned error: %v", err)
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusTooManyRequests)
	}
	if called != 0 {
		t.Fatalf("upstream should not be called when rate limited, called=%d", called)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want %q", got, "no-store")
	}
	if got := rec.Header().Get("Surrogate-Control"); got != "no-store" {
		t.Fatalf("Surrogate-Control = %q, want %q", got, "no-store")
	}
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Fatalf("Retry-After = %q, want %q", got, "1")
	}
}
