package mtlswhitelist

import (
	"fmt"
	"net"
	"os"
	"strings"
)

func getDefaultGatewayInterface() (string, error) {
	// Read the /proc/net/route file
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return "", err
	}

	// Parse the file to find the default gateway interface
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		fields := strings.Split(line, "\t")
		if len(fields) > 0 && fields[1] == "00000000" && fields[7] == "00000000" {
			// Found the default gateway, extract the interface name
			ifaceName := fields[0]
			return ifaceName, nil
		}
	}

	return "", fmt.Errorf("default gateway interface not found")
}

func getIPv4AddressRanges(ifaceName string) ([]string, error) {
	var ipv4Ranges []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if iface.Name == ifaceName {
			addrs, err := iface.Addrs()
			if err != nil {
				return nil, err
			}

			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}

				if ip.To4() != nil {
					mask, ok := addr.(*net.IPNet)
					if ok && mask.IP.To4() != nil {
						ones, _ := mask.Mask.Size()
						ipRange := fmt.Sprintf("%s/%v", ip, ones)
						ipv4Ranges = append(ipv4Ranges, ipRange)
					}
				}
			}
		}
	}

	return ipv4Ranges, nil
}

func getIPv6AddressRanges(ifaceName string) ([]string, error) {
	var ipv6Ranges []string
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range interfaces {
		if iface.Name == ifaceName {
			addrs, err := iface.Addrs()
			if err != nil {
				return nil, err
			}

			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}

				if ip.To4() == nil {
					mask, ok := addr.(*net.IPNet)
					if ok && ip.To16() != nil {
						ones, _ := mask.Mask.Size()
						ipRange := fmt.Sprintf("%s/%v", ip, ones)
						ipv6Ranges = append(ipv6Ranges, ipRange)
					}
				}
			}
		}
	}

	return ipv6Ranges, nil
}
