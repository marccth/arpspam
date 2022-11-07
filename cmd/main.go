package main

import (
	"log"

	"github.com/marccth/arpspam/internal/flagger"
	"github.com/marccth/arpspam/internal/service"
)

func main() {
	flags := flagger.ParseFlags()
	if flags == nil {
		return
	}

	svc := service.NewService(flags.Mode, flags.Target, flags.Iface, flags.ARPCount, flags.ARPInterval)
	err := svc.Run()
	if err != nil {
		log.Fatal(err)
	}
}
