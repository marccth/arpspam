package flagger

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/marccth/arpspam/internal/service"
	"github.com/marccth/arpspam/internal/utils"
)

const usageText = `
Usage:

  arpspam -t [IP address to spoof] -iface [interface name]

	-t		The IP address you want to spoof. Ex: 192.168.1.99
	-iface		The network interface you want to use. Ex: en0

  Optional flags:
	-m		The mode you want to run. "flood" writes gratuitious replies. "passive" only responds to ARP requests. (default "passive")
	-c		The number of ARP replies to send every burst. Ex: 15 (default 5)
	-i		Interval in seconds between each burst of ARP replies if flood mode enabled. Ex: 45 (default 30)

  Additional flags:
	-h		Print the list of available commands.
	-list-iface	Print the list of available IPv4 interfaces.

`

type Flags struct {
	Mode        service.ServiceMode
	Target      string
	Iface       string
	ARPCount    uint
	ARPInterval uint
}

func ParseFlags() *Flags {
	// Define new flag set so we can suppress built-in errors
	fs := flag.NewFlagSet("arpspam", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	var (
		modeFlag    = fs.String("m", "passive", `The mode you want to run. "flood" writes gratuitious replies. "passive" only responds to ARP requests`)
		targetFlag  = fs.String("t", "", "The IP address you want to spoof. Ex: 192.168.1.99")
		ifaceFlag   = fs.String("iface", "", "The network interface you want to use. Ex: en0")
		arpCount    = fs.Uint("c", 5, "The number of ARP replies to send every burst. Ex: 15")
		arpInterval = fs.Uint("i", 30, "Number of seconds between each burst of ARP replies if flood mode enabled. Ex: 45")
		printHelp   = fs.Bool("h", false, "Print the list of available commands.")
		printIfaces = fs.Bool("list-iface", false, "Print the list of available IPv4 interfaces.")
	)

	// Parse flag input
	fs.Parse(os.Args[1:])

	// Print help if requested
	if *printHelp {
		PrintUsageText()
		return nil
	}

	// Print the IPv4 interfaces if requested
	if *printIfaces {
		utils.PrintIfaces()
		return nil
	}

	// Validate target
	if len(*targetFlag) < 1 {
		fmt.Println("\nPlease specify a target IP address")
		PrintUsageText()
		return nil
	}

	// Validate interface
	if len(*ifaceFlag) < 1 {
		fmt.Println("\nPlease specify your interface name")
		PrintUsageText()
		return nil
	}

	// Validate mode
	mode := service.ServiceMode(*modeFlag)
	if !((mode == service.Passive_Mode) || (mode == service.Flood_Mode)) {
		fmt.Println("\nPlease specify a valid mode")
		PrintUsageText()
		return nil
	}

	return &Flags{
		Mode:        mode,
		Target:      *targetFlag,
		Iface:       *ifaceFlag,
		ARPCount:    *arpCount,
		ARPInterval: *arpInterval,
	}
}

// PrintUsageText prints the contents of the usageText constant
func PrintUsageText() {
	fmt.Printf(usageText)
}
