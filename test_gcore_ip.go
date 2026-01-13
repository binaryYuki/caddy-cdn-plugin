//go:build ignore

package edge

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// Test script to verify Gcore IP list fetching and matching
// Run with: go run test_gcore_ip.go [test_ip]
// Example: go run test_gcore_ip.go 93.123.17.151

const (
	gcoreIPURL  = "https://api.gcore.com/cdn/public-ip-list"
	gcoreNetURL = "https://api.gcore.com/cdn/public-net-list"
)

func main() {
	// Setup log with timestamp, auto-rotate after 5 minutes worth of logs
	log.SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds)
	log.SetOutput(os.Stdout)

	startTime := time.Now()
	log.Printf("=== Gcore IP Test Started ===")
	defer func() {
		log.Printf("=== Test completed in %v ===", time.Since(startTime))
	}()

	// Default test IPs
	testIPs := []string{"93.123.17.151", "81.28.12.12"}

	// Allow custom test IP from command line
	if len(os.Args) > 1 {
		testIPs = os.Args[1:]
	}

	log.Printf("Test IPs: %v", testIPs)

	// Fetch both Gcore APIs
	allCIDRs := []string{}

	for _, url := range []string{gcoreIPURL, gcoreNetURL} {
		log.Printf("Fetching: %s", url)
		fetchStart := time.Now()

		cidrs, ipv4Count, ipv6Count, err := fetchGcoreAPI(url)
		if err != nil {
			log.Printf("ERROR fetching %s: %v", url, err)
			continue
		}

		log.Printf("  -> %d IPv4, %d IPv6 (took %v)", ipv4Count, ipv6Count, time.Since(fetchStart))
		allCIDRs = append(allCIDRs, cidrs...)
	}

	log.Printf("Total raw CIDRs fetched: %d", len(allCIDRs))

	// Parse into networks
	parseStart := time.Now()
	var networks []net.IPNet
	var parseErrors int

	for _, cidr := range allCIDRs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}

		// Add /32 or /128 for single IPs
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
			parseErrors++
			if parseErrors <= 5 {
				log.Printf("  WARN: failed to parse CIDR '%s': %v", cidr, err)
			}
			continue
		}
		networks = append(networks, *ipNet)
	}

	log.Printf("Parsed %d networks (errors: %d, took %v)", len(networks), parseErrors, time.Since(parseStart))

	// Check test IPs
	log.Printf("")
	log.Printf("=== Testing IP Matching ===")

	for _, testIP := range testIPs {
		checkIP(testIP, networks)
	}

	// Log retention notice
	log.Printf("")
	log.Printf("Note: This test output should be retained for max 5 minutes for debugging")
}

func fetchGcoreAPI(url string) ([]string, int, int, error) {
	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Get(url)
	if err != nil {
		return nil, 0, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, 0, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, 0, 0, err
	}

	var result struct {
		Addresses   []string `json:"addresses"`
		AddressesV6 []string `json:"addresses_v6"`
	}
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, 0, 0, fmt.Errorf("JSON parse error: %w", err)
	}

	all := make([]string, 0, len(result.Addresses)+len(result.AddressesV6))
	all = append(all, result.Addresses...)
	all = append(all, result.AddressesV6...)

	return all, len(result.Addresses), len(result.AddressesV6), nil
}

func checkIP(testIP string, networks []net.IPNet) {
	ip := net.ParseIP(testIP)
	if ip == nil {
		log.Printf("  %s: FAILED to parse IP", testIP)
		return
	}

	// Normalize to IPv4 if applicable
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}

	matchStart := time.Now()
	for _, n := range networks {
		if n.Contains(ip) {
			log.Printf("  %s: ✓ FOUND in %s (checked in %v)", testIP, n.String(), time.Since(matchStart))
			return
		}
	}

	log.Printf("  %s: ✗ NOT FOUND in any of %d networks (checked in %v)", testIP, len(networks), time.Since(matchStart))

	// Try to find similar networks for debugging
	ipParts := strings.Split(testIP, ".")
	if len(ipParts) >= 2 {
		prefix := ipParts[0] + "." + ipParts[1]
		log.Printf("    Searching for networks starting with %s.*...", prefix)
		found := 0
		for _, n := range networks {
			if strings.HasPrefix(n.IP.String(), prefix) {
				log.Printf("      Similar: %s", n.String())
				found++
				if found >= 5 {
					log.Printf("      ... (more omitted)")
					break
				}
			}
		}
		if found == 0 {
			log.Printf("      No networks found with prefix %s.*", prefix)
		}
	}
}
