package mtlswhitelist

import (
	"errors"
	"fmt"
	"net"
	"net/http"
)

type RuleIPRange struct {
	Ranges       []string `json:"ranges"`
	AddInterface bool     `json:"addInterface,omitempty"`

	// Internal
	allowedCidrs []*net.IPNet
}

func (r *RuleIPRange) Init() error {
	netCidrs := make([]*net.IPNet, 0, len(r.Ranges))

	fmt.Printf("Ranges: %v", r.Ranges)
	for _, cidr := range r.Ranges {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return fmt.Errorf("invalid cidr: %s %w", cidr, err)
		}
		netCidrs = append(netCidrs, ipNet)
	}
	if r.AddInterface {
		interfaceCidrs, neterr := scanInterfaces()
		if neterr != nil {
			return neterr
		}
		netCidrs = append(netCidrs, interfaceCidrs...)
	}

	r.allowedCidrs = netCidrs

	fmt.Println("Allowed CIDRs: ", r.allowedCidrs)

	if len(r.allowedCidrs) == 0 {
		return errors.New("no ranges provided")
	}

	return nil
}

func (r *RuleIPRange) Match(req *http.Request) bool {
	realIP := req.Header.Get("X-Real-Ip")
	if realIP == "" {
		realIP = req.Header.Get("X-Forwarded-For")
	}
	allowed, cidr := r.isIPInRange(realIP)
	if allowed {
		req.Header.Set("X-Whitelist-Cidr", cidr)
	}

	return allowed
}

func (r *RuleIPRange) isIPInRange(ip string) (bool, string) {
	realIP := net.ParseIP(ip)
	if realIP == nil {
		return false, ""
	}

	for _, cidr := range r.allowedCidrs {
		if cidr.Contains(realIP) {
			return true, cidr.String()
		}
	}
	return false, ""
}

func scanInterfaces() ([]*net.IPNet, error) {
	netCidrs := make([]*net.IPNet, 0)
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
		_, ipNet, iperr := net.ParseCIDR(ipRange)
		if iperr != nil {
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

	return netCidrs, nil
}
