// Package plugindemo a demo plugin.
package mtlswhitelist

import (
	"context"
	"fmt"
	"net"
	"net/http"
)

// Config the plugin configuration.
type Config struct {
	AllowedCidrs       []string `json:"whitelist,omitempty"`
	WhitelistInterface bool     `json:"whitelistInterface,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		AllowedCidrs:       []string{},
		WhitelistInterface: false,
	}
}

// Demo a Demo plugin.
type MTlsOrWhitelist struct {
	next         http.Handler
	AllowedCidrs []*net.IPNet
	name         string
}

// New created a new Demo plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.AllowedCidrs) == 0 {
		return nil, fmt.Errorf("no cidrs provided")
	}
	netCidrs := make([]*net.IPNet, 0, len(config.AllowedCidrs))

	for _, cidr := range config.AllowedCidrs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid cidr: %s", cidr)
		}
		netCidrs = append(netCidrs, ipNet)
	}

	if config.WhitelistInterface {
		ifaceName, err := getDefaultGatewayInterface()
		if err != nil {
			return nil, fmt.Errorf("failed to get default gateway interface: %w", err)
		}
		fmt.Println("Default Gateway Interface: ", ifaceName)
		ipv4Ranges, err := getIPv4AddressRanges(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("failed to get ipv4 address ranges: %w", err)
		}
		fmt.Println("IPv4 Address Ranges: ", ipv4Ranges)
		for _, ipRange := range ipv4Ranges {
			_, ipNet, err := net.ParseCIDR(ipRange)
			if err != nil {
				return nil, fmt.Errorf("invalid cidr: %s", ipRange)
			}
			netCidrs = append(netCidrs, ipNet)
		}
		ipv6Ranges, err := getIPv6AddressRanges(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("failed to get ipv6 address ranges: %w", err)
		}
		fmt.Println("IPv6 Address Ranges: ", ipv6Ranges)
		for _, ipRange := range ipv6Ranges {
			_, ipNet, err := net.ParseCIDR(ipRange)
			if err != nil {
				return nil, fmt.Errorf("invalid cidr: %s", ipRange)
			}
			netCidrs = append(netCidrs, ipNet)
		}
	}

	fmt.Printf("Allowed CIDRs: %v\n", netCidrs)

	return &MTlsOrWhitelist{
		next:         next,
		name:         name,
		AllowedCidrs: netCidrs,
	}, nil
}

func (a *MTlsOrWhitelist) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if req.TLS != nil && len(req.TLS.PeerCertificates) > 0 {
		fmt.Println("Client Certificate: ", req.TLS.PeerCertificates[0].Subject)
		req.Header.Set("X-Client-Cert-SN", req.TLS.PeerCertificates[0].SerialNumber.String())
		req.Header.Set("X-Client-Cert-CN", req.TLS.PeerCertificates[0].Subject.CommonName)
		a.next.ServeHTTP(rw, req)
		return
	}

	// if no cert provided check if request came from accepted ips
	realIp := req.Header.Get("X-Real-Ip")
	if realIp == "" {
		realIp = req.Header.Get("X-Forwarded-For")
	}
	fmt.Println("Real IP: ", realIp)

	// if no cert provided and request is not from accepted ips, set SN to NoCert
	req.Header.Set("X-Client-Cert-SN", "NoCert")

	allowed, cidr := a.isIPInRange(realIp)
	if !allowed {
		http.Error(rw, "Forbidden", http.StatusForbidden)
		return
	}
	req.Header.Set("X-Client-Cidr", cidr)

	a.next.ServeHTTP(rw, req)
}

func (a *MTlsOrWhitelist) isIPInRange(ip string) (bool, string) {
	realIP := net.ParseIP(ip)
	if realIP == nil {
		return false, ""
	}

	for _, cidr := range a.AllowedCidrs {
		if cidr.Contains(realIP) {
			return true, cidr.String()
		}
	}

	return false, ""
}
