#  arpspam

## Summary
This is a simple tool you can use to perform ARP spoofing attacks. It was written mostly for the purposes of testing out the gopacket library.

You can run this tool in either `passive` mode or `flood` mode:
* Passive mode listens for ARP Request packets for the IP address you are attempting to spoof. It will respond with an ARP Reply to the requester.
* Flood mode broadcasts gratuitious ARP Reply packets on a timed schedule.

At a minimum, you need to provide the IP address you are spoofing and the name of your relevant network interface. If you do not specify a mode, it will run in `passive` mode.

## Usage
```
  arpspam -t [IP address to spoof] -iface [interface name]
  
	-t              The IP address you want to spoof. Ex: 192.168.1.99
	-iface          The network interface you want to use. Ex: en0

  Optional flags:
	-m              The mode you want to run. "flood" writes gratuitious replies. "passive" only responds to ARP requests. (default "passive")
	-c              The number of ARP replies to send every burst. Ex: 15 (default 5)
	-i              Interval in seconds between each burst of ARP replies if flood mode enabled. Ex: 45 (default 30)

  Additional flags:
	-h              Print the list of available commands.
	-list-iface     Print the list of available IPv4 interfaces.

```
