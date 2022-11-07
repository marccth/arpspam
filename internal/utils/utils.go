package utils

import (
	"fmt"
	"net"
	"os"
	"text/tabwriter"
)

type ifaceFormatted struct {
	Name   string
	HWAddr string
	Addr   *net.IPNet
}

// PrintIfaces prints a list of IPv4 interfaces alongside their IP address/mask and MAC
func PrintIfaces() {
	results := []*ifaceFormatted{}

	// Get list of interfaces
	ifsList, _ := net.Interfaces()
	for _, ifs := range ifsList {
		// Get addresses for interface
		addrs, err := ifs.Addrs()
		if err != nil {
			continue
		}

		// We will return the first IPv4 address on this interface
		var addr *net.IPNet
		for _, a := range addrs {
			// Assume each address is of type net.IPNet
			if ipnet, ok := a.(*net.IPNet); ok {
				// If ipnet.IP.To4() is not nil, then this is an IPv4 addr
				if ip4 := ipnet.IP.To4(); ip4 != nil {
					addr = &net.IPNet{
						IP:   ip4,
						Mask: ipnet.Mask,
					}
					break
				}
			}
		}

		// If the interface has an IPv4 address, we will print it
		if addr != nil {
			results = append(results, &ifaceFormatted{
				Name:   ifs.Name,
				Addr:   addr,
				HWAddr: ifs.HardwareAddr.String(),
			})
		}
	}

	// Format and print the results using tabwriter
	writer := tabwriter.NewWriter(os.Stdout, 18, 0, 0, ' ', tabwriter.Debug)
	defer writer.Flush()
	fmt.Fprintf(writer, "\nInterface\tIP Address\tMAC Address\t\n")
	fmt.Fprintf(writer, "------------------\t------------------\t------------------\t\n")
	for i := 0; i < len(results); i++ {
		result := results[i]
		fmt.Fprintf(writer, "%s\t%s\t%s\t\n", result.Name, result.Addr, result.HWAddr)
	}
}
