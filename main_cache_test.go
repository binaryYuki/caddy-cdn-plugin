package edge

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSetNoStoreCacheHeaders(t *testing.T) {
	h := make(http.Header)
	setNoStoreCacheHeaders(h)

	if got := h.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want %q", got, "no-store")
	}
	if got := h.Get("Surrogate-Control"); got != "no-store" {
		t.Fatalf("Surrogate-Control = %q, want %q", got, "no-store")
	}
}

func TestSetNoCacheRevalidateHeaders(t *testing.T) {
	h := make(http.Header)
	setNoCacheRevalidateHeaders(h)

	if got := h.Get("Cache-Control"); got != "no-cache, must-revalidate" {
		t.Fatalf("Cache-Control = %q, want %q", got, "no-cache, must-revalidate")
	}
	if got := h.Get("Surrogate-Control"); got != "no-cache" {
		t.Fatalf("Surrogate-Control = %q, want %q", got, "no-cache")
	}
}

func TestSetOKCacheHeaders(t *testing.T) {
	h := make(http.Header)
	setOKCacheHeaders(h, 600)

	if got := h.Get("Cache-Control"); got != "public, max-age=0, must-revalidate" {
		t.Fatalf("Cache-Control = %q, want %q", got, "public, max-age=0, must-revalidate")
	}
	if got := h.Get("Surrogate-Control"); got != "max-age=600" {
		t.Fatalf("Surrogate-Control = %q, want %q", got, "max-age=600")
	}
}

func TestEdgeRWWriteHeaderSetsSurrogateControlForOK(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://cdn.example.com/assets/app.js", nil)

	rw := &edgeRW{
		ResponseWriter: rec,
		req:            req,
		cfg: &Edge{
			XServer:        "test-edge",
			OkCacheSeconds: 120,
		},
	}

	rw.WriteHeader(http.StatusOK)

	if got := rec.Header().Get("Surrogate-Control"); got != "max-age=120" {
		t.Fatalf("Surrogate-Control = %q, want %q", got, "max-age=120")
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=0, must-revalidate" {
		t.Fatalf("Cache-Control = %q, want %q", got, "public, max-age=0, must-revalidate")
	}
	if strings.Contains(rec.Header().Get("Cache-Control"), "s-maxage") {
		t.Fatalf("Cache-Control should not include s-maxage after split policy: %q", rec.Header().Get("Cache-Control"))
	}
}
