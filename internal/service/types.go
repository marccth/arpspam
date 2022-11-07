package service

type ServiceMode string

const (
	Passive_Mode ServiceMode = "passive"
	Flood_Mode   ServiceMode = "flood"
)

type Service struct {
	Mode        ServiceMode
	Target      string
	Iface       string
	ARPCount    uint
	ARPInterval uint
}

func NewService(mode ServiceMode, target string, iface string, arpCount uint, arpInterval uint) *Service {
	return &Service{
		Mode:        mode,
		Target:      target,
		Iface:       iface,
		ARPCount:    arpCount,
		ARPInterval: arpInterval,
	}
}
