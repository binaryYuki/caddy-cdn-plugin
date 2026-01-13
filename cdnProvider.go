package edge

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

// CDNProvider represents a CDN provider name
type CDNProvider string

const (
	CDNCloudflare CDNProvider = "cloudflare"
	CDNGcore      CDNProvider = "gcore"
	CDNFastly     CDNProvider = "fastly"
)

// CDN IP list URLs
const (
	cloudflareIPv4URL = "https://www.cloudflare.com/ips-v4/"
	cloudflareIPv6URL = "https://www.cloudflare.com/ips-v6/"
	gcoreIPURL        = "https://api.gcore.com/cdn/public-ip-list"
	gcoreNetURL       = "https://api.gcore.com/cdn/public-net-list"
	fastlyIPURL       = "https://api.fastly.com/public-ip-list"
)

// Default refresh interval
const defaultRefreshInterval = 1 * time.Hour

// CDNWhitelist manages CDN IP whitelisting
type CDNWhitelist struct {
	provider CDNProvider
	logger   *zap.Logger

	// Atomic pointer to current IP networks for lock-free reads
	networks atomic.Pointer[[]net.IPNet]

	// For graceful shutdown
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// HTTP client with timeout
	httpClient *http.Client

	// Refresh interval
	refreshInterval time.Duration
}

// NewCDNWhitelist creates a new CDN whitelist manager
func NewCDNWhitelist(provider CDNProvider, logger *zap.Logger) *CDNWhitelist {
	ctx, cancel := context.WithCancel(context.Background())

	w := &CDNWhitelist{
		provider:        provider,
		logger:          logger,
		ctx:             ctx,
		cancel:          cancel,
		refreshInterval: defaultRefreshInterval,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				IdleConnTimeout:     90 * time.Second,
				DisableCompression:  false,
				DisableKeepAlives:   false,
				MaxIdleConnsPerHost: 5,
			},
		},
	}

	// Initialize with empty list
	empty := make([]net.IPNet, 0)
	w.networks.Store(&empty)

	return w
}

// Start begins the periodic IP list refresh
func (w *CDNWhitelist) Start() error {
	// Do initial fetch synchronously
	if err := w.refresh(); err != nil {
		w.logger.Error("initial CDN IP fetch failed",
			zap.String("provider", string(w.provider)),
			zap.Error(err))
		// Don't return error - start anyway and retry
	}

	// Start background refresh goroutine
	w.wg.Add(1)
	go w.refreshLoop()

	return nil
}

// Stop stops the periodic refresh
func (w *CDNWhitelist) Stop() {
	w.cancel()
	w.wg.Wait()
}

// IsAllowed checks if the given IP is in the CDN whitelist
// This is lock-free for maximum performance on the hot path
func (w *CDNWhitelist) IsAllowed(ip net.IP) bool {
	if ip == nil {
		return false
	}

	networks := w.networks.Load()
	if networks == nil || len(*networks) == 0 {
		// No networks loaded yet, allow (fail-open during startup)
		// Or deny for stricter security: return false
		return true
	}

	for _, n := range *networks {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// IsAllowedString checks if the given IP string is in the CDN whitelist
func (w *CDNWhitelist) IsAllowedString(ipStr string) bool {
	allowed, _ := w.IsAllowedStringDebug(ipStr)
	return allowed
}

// IsAllowedStringDebug checks if the given IP string is in the CDN whitelist
// and returns a reason string for debugging
func (w *CDNWhitelist) IsAllowedStringDebug(ipStr string) (bool, string) {
	// Handle host:port format (e.g., "192.168.1.1:12345")
	host := ipStr
	if h, _, err := net.SplitHostPort(ipStr); err == nil {
		host = h
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false, fmt.Sprintf("failed to parse IP from '%s' (extracted host: '%s')", ipStr, host)
	}

	networks := w.networks.Load()
	if networks == nil {
		return true, "networks is nil (fail-open)"
	}
	if len(*networks) == 0 {
		return true, "no networks loaded (fail-open)"
	}

	// Normalize IP for comparison
	normalizedIP := ip
	if ip4 := ip.To4(); ip4 != nil {
		normalizedIP = ip4
	}

	for _, n := range *networks {
		if n.Contains(normalizedIP) {
			return true, fmt.Sprintf("matched network %s", n.String())
		}
	}
	return false, fmt.Sprintf("IP %s (from %s) not in %d networks", normalizedIP.String(), ipStr, len(*networks))
}

// refreshLoop runs the periodic refresh
func (w *CDNWhitelist) refreshLoop() {
	defer w.wg.Done()

	ticker := time.NewTicker(w.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-w.ctx.Done():
			return
		case <-ticker.C:
			if err := w.refresh(); err != nil {
				w.logger.Error("CDN IP refresh failed",
					zap.String("provider", string(w.provider)),
					zap.Error(err))
			}
		}
	}
}

// refresh fetches the latest IP list from the CDN provider
func (w *CDNWhitelist) refresh() error {
	var cidrs []string
	var err error

	w.logger.Info("starting CDN IP list refresh",
		zap.String("provider", string(w.provider)))

	startTime := time.Now()

	switch w.provider {
	case CDNCloudflare:
		cidrs, err = w.fetchCloudflare()
	case CDNGcore:
		cidrs, err = w.fetchGcore()
	case CDNFastly:
		cidrs, err = w.fetchFastly()
	default:
		return fmt.Errorf("unknown CDN provider: %s", w.provider)
	}

	fetchDuration := time.Since(startTime)

	if err != nil {
		w.logger.Error("failed to fetch CDN IP list",
			zap.String("provider", string(w.provider)),
			zap.Duration("duration", fetchDuration),
			zap.Error(err))
		return err
	}

	w.logger.Debug("fetched CDN IP list",
		zap.String("provider", string(w.provider)),
		zap.Duration("duration", fetchDuration),
		zap.Int("raw_cidr_count", len(cidrs)))

	// Parse CIDRs into IPNet
	networks := make([]net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" || strings.HasPrefix(cidr, "#") {
			continue
		}

		// Handle single IP (add /32 or /128)
		if !strings.Contains(cidr, "/") {
			ip := net.ParseIP(cidr)
			if ip != nil {
				if ip.To4() != nil {
					cidr = cidr + "/32"
				} else {
					cidr = cidr + "/128"
				}
			}
		}

		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			w.logger.Warn("invalid CIDR",
				zap.String("cidr", cidr),
				zap.Error(err))
			continue
		}
		networks = append(networks, *ipNet)
	}

	// Atomically update the networks
	w.networks.Store(&networks)

	w.logger.Info("CDN IP list refreshed",
		zap.String("provider", string(w.provider)),
		zap.Int("count", len(networks)))

	return nil
}

// fetchCloudflare fetches Cloudflare IP ranges
func (w *CDNWhitelist) fetchCloudflare() ([]string, error) {
	var cidrs []string

	// Fetch IPv4
	ipv4, err := w.fetchTextList(cloudflareIPv4URL)
	if err != nil {
		return nil, fmt.Errorf("fetch cloudflare ipv4: %w", err)
	}
	cidrs = append(cidrs, ipv4...)

	// Fetch IPv6
	ipv6, err := w.fetchTextList(cloudflareIPv6URL)
	if err != nil {
		return nil, fmt.Errorf("fetch cloudflare ipv6: %w", err)
	}
	cidrs = append(cidrs, ipv6...)

	return cidrs, nil
}

// fetchGcore fetches Gcore IP ranges from both public-ip-list and public-net-list
func (w *CDNWhitelist) fetchGcore() ([]string, error) {
	var allCIDRs []string

	// Fetch from public-ip-list (individual IPs)
	ipList, err := w.fetchGcoreAPI(gcoreIPURL)
	if err != nil {
		return nil, fmt.Errorf("fetch gcore public-ip-list: %w", err)
	}
	allCIDRs = append(allCIDRs, ipList...)

	w.logger.Debug("fetched gcore public-ip-list",
		zap.Int("count", len(ipList)))

	// Fetch from public-net-list (network ranges)
	netList, err := w.fetchGcoreAPI(gcoreNetURL)
	if err != nil {
		return nil, fmt.Errorf("fetch gcore public-net-list: %w", err)
	}
	allCIDRs = append(allCIDRs, netList...)

	w.logger.Debug("fetched gcore public-net-list",
		zap.Int("count", len(netList)))

	return allCIDRs, nil
}

// fetchGcoreAPI fetches IP addresses from a Gcore API endpoint
func (w *CDNWhitelist) fetchGcoreAPI(url string) ([]string, error) {
	req, err := http.NewRequestWithContext(w.ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			w.logger.Warn("error closing Gcore response body", zap.Error(err))
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gcore API %s returned status %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		return nil, err
	}

	// Gcore returns JSON: {"addresses": ["ip1", "ip2", ...], "addresses_v6": [...]}
	var result struct {
		Addresses   []string `json:"addresses"`
		AddressesV6 []string `json:"addresses_v6"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse gcore response from %s: %w", url, err)
	}

	// Combine IPv4 and IPv6 addresses
	all := make([]string, 0, len(result.Addresses)+len(result.AddressesV6))
	all = append(all, result.Addresses...)
	all = append(all, result.AddressesV6...)

	return all, nil
}

// fetchFastly fetches Fastly IP ranges
func (w *CDNWhitelist) fetchFastly() ([]string, error) {
	req, err := http.NewRequestWithContext(w.ctx, http.MethodGet, fastlyIPURL, nil)
	if err != nil {
		return nil, err
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			w.logger.Error("failed to close response body", zap.Error(err))
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fastly API returned status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024)) // 10MB limit
	if err != nil {
		return nil, err
	}

	// Fastly returns JSON: {"addresses": ["cidr1", ...], "ipv6_addresses": ["cidr2", ...]}
	var result struct {
		Addresses     []string `json:"addresses"`
		IPv6Addresses []string `json:"ipv6_addresses"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("parse fastly response: %w", err)
	}

	cidrs := make([]string, 0, len(result.Addresses)+len(result.IPv6Addresses))
	cidrs = append(cidrs, result.Addresses...)
	cidrs = append(cidrs, result.IPv6Addresses...)

	return cidrs, nil
}

// fetchTextList fetches a newline-separated list of CIDRs
func (w *CDNWhitelist) fetchTextList(url string) ([]string, error) {
	req, err := http.NewRequestWithContext(w.ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := w.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			w.logger.Error("failed to close response body", zap.Error(err))
		}
	}(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("URL %s returned status %d", url, resp.StatusCode)
	}

	var cidrs []string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			cidrs = append(cidrs, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return cidrs, nil
}

// Global whitelist registry (for multiple providers)
var (
	whitelistRegistry   = make(map[CDNProvider]*CDNWhitelist)
	whitelistRegistryMu sync.RWMutex
)

// GetOrCreateWhitelist gets or creates a whitelist for the given provider
func GetOrCreateWhitelist(provider CDNProvider, logger *zap.Logger) (*CDNWhitelist, error) {
	whitelistRegistryMu.Lock()
	defer whitelistRegistryMu.Unlock()

	if w, ok := whitelistRegistry[provider]; ok {
		return w, nil
	}

	w := NewCDNWhitelist(provider, logger)
	if err := w.Start(); err != nil {
		return nil, err
	}

	whitelistRegistry[provider] = w
	return w, nil
}

// CleanupWhitelists stops all whitelists (call on shutdown)
func CleanupWhitelists() {
	whitelistRegistryMu.Lock()
	defer whitelistRegistryMu.Unlock()

	for _, w := range whitelistRegistry {
		w.Stop()
	}
	whitelistRegistry = make(map[CDNProvider]*CDNWhitelist)
}

// Register cleanup on Caddy exit
func init() {
	caddy.RegisterModule(cdnWhitelistCleanup{})
}

type cdnWhitelistCleanup struct{}

func (cdnWhitelistCleanup) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "caddy.listeners.cdn_whitelist_cleanup",
		New: func() caddy.Module { return new(cdnWhitelistCleanup) },
	}
}

func (c *cdnWhitelistCleanup) Cleanup() error {
	CleanupWhitelists()
	return nil
}

var _ caddy.CleanerUpper = (*cdnWhitelistCleanup)(nil)
