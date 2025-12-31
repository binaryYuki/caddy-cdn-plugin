package edge

import (
	"net"
	"testing"

	"go.uber.org/zap"
)

func TestCDNWhitelist_IsAllowed(t *testing.T) {
	logger := zap.NewNop()
	w := NewCDNWhitelist(CDNCloudflare, logger)

	// Manually add some test networks
	testNetworks := []net.IPNet{
		mustParseCIDR("103.21.244.0/22"),
		mustParseCIDR("2400:cb00::/32"),
		mustParseCIDR("192.168.1.100/32"),
	}
	w.networks.Store(&testNetworks)

	tests := []struct {
		name    string
		ip      string
		allowed bool
	}{
		{"Cloudflare IPv4 in range", "103.21.244.1", true},
		{"Cloudflare IPv4 in range 2", "103.21.245.100", true},
		{"Cloudflare IPv6 in range", "2400:cb00::1", true},
		{"Single IP match", "192.168.1.100", true},
		{"Not in range", "1.2.3.4", false},
		{"Not in range 2", "10.0.0.1", false},
		{"Empty string", "", false},
		{"Invalid IP", "not-an-ip", false},
		{"Host:port format", "103.21.244.1:8080", true},
		{"IPv6 with port", "[2400:cb00::1]:443", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := w.IsAllowedString(tt.ip)
			if got != tt.allowed {
				t.Errorf("IsAllowedString(%q) = %v, want %v", tt.ip, got, tt.allowed)
			}
		})
	}
}

func TestCDNWhitelist_EmptyNetworks(t *testing.T) {
	logger := zap.NewNop()
	w := NewCDNWhitelist(CDNCloudflare, logger)

	// Empty networks should allow (fail-open)
	if !w.IsAllowedString("1.2.3.4") {
		t.Error("Empty networks should allow requests (fail-open)")
	}
}

func TestCDNProvider_Values(t *testing.T) {
	tests := []struct {
		provider CDNProvider
		expected string
	}{
		{CDNCloudflare, "cloudflare"},
		{CDNGcore, "gcore"},
		{CDNFastly, "fastly"},
	}

	for _, tt := range tests {
		if string(tt.provider) != tt.expected {
			t.Errorf("CDNProvider %v != %v", tt.provider, tt.expected)
		}
	}
}

func mustParseCIDR(s string) net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic(err)
	}
	return *ipNet
}

func BenchmarkIsAllowed(b *testing.B) {
	logger := zap.NewNop()
	w := NewCDNWhitelist(CDNCloudflare, logger)

	// Simulate realistic Cloudflare IP list size (~15 IPv4 + ~7 IPv6 ranges)
	testNetworks := []net.IPNet{
		mustParseCIDR("103.21.244.0/22"),
		mustParseCIDR("103.22.200.0/22"),
		mustParseCIDR("103.31.4.0/22"),
		mustParseCIDR("104.16.0.0/13"),
		mustParseCIDR("104.24.0.0/14"),
		mustParseCIDR("108.162.192.0/18"),
		mustParseCIDR("131.0.72.0/22"),
		mustParseCIDR("141.101.64.0/18"),
		mustParseCIDR("162.158.0.0/15"),
		mustParseCIDR("172.64.0.0/13"),
		mustParseCIDR("173.245.48.0/20"),
		mustParseCIDR("188.114.96.0/20"),
		mustParseCIDR("190.93.240.0/20"),
		mustParseCIDR("197.234.240.0/22"),
		mustParseCIDR("198.41.128.0/17"),
		mustParseCIDR("2400:cb00::/32"),
		mustParseCIDR("2606:4700::/32"),
		mustParseCIDR("2803:f800::/32"),
		mustParseCIDR("2405:b500::/32"),
		mustParseCIDR("2405:8100::/32"),
		mustParseCIDR("2a06:98c0::/29"),
		mustParseCIDR("2c0f:f248::/32"),
	}
	w.networks.Store(&testNetworks)

	testIP := net.ParseIP("104.16.1.1") // A Cloudflare IP

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		w.IsAllowed(testIP)
	}
}

func BenchmarkIsAllowedString(b *testing.B) {
	logger := zap.NewNop()
	w := NewCDNWhitelist(CDNCloudflare, logger)

	testNetworks := []net.IPNet{
		mustParseCIDR("103.21.244.0/22"),
		mustParseCIDR("104.16.0.0/13"),
		mustParseCIDR("2400:cb00::/32"),
	}
	w.networks.Store(&testNetworks)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		w.IsAllowedString("104.16.1.1:443")
	}
}
