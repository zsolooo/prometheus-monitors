package main

import (
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"code.google.com/p/gopacket/pcap"
	"flag"
	"github.com/prometheus/client_golang/prometheus"
	"log"
	"net/http"
)

const (
	_ = byte(iota)
	DHCPDISCOVER
	DHCPOFFER
	DHCPREQUEST
	DHCPDECLINE
	DHCPACK
	DHCPNAK
	DHCPRELEASE
	DHCPINFORM
)

var addr = flag.String("listen-address", ":8080", "The address to listen on for HTTP requests.")
var iface = flag.String("interface", "eth0", "The interface where you want to capture DHCP packets.")

var dhcpPacketCount = prometheus.NewCounterVec(prometheus.CounterOpts{
	Name: "dhcp_packets",
	Help: "Number of DHCP packets captured, partitioned by source MAC addresses",
}, []string{"SrcMAC"})

func init() {
	flag.Parse()
	prometheus.MustRegister(dhcpPacketCount)
}

func main() {
	log.Println("Opening live capture on", *iface)
	handle, err := pcap.OpenLive(*iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	log.Println("Setting filter for UDP source port 67.")
	if err := handle.SetBPFFilter("udp and src port 67"); err != nil {
		log.Fatal(err)
	}

	go func() {
		log.Println("Start listening for packets.")
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			go checkPacket(&packet)
		}
	}()

	log.Println("Registering metrics handler.")
	http.Handle("/metrics", prometheus.Handler())
	log.Println("Listening on", *addr)
	if err := http.ListenAndServe(*addr, nil); err != nil {
		panic(err.Error())
	}

}

func checkPacket(packet *gopacket.Packet) {
	ethLayer := (*packet).Layer(layers.LayerTypeEthernet)
	if ethLayer == nil {
		return
	}

	ethernet := ethLayer.(*layers.Ethernet)
	p := (*packet).Data()
	log.Println(ethernet.SrcMAC.String())
	if 0x11C <= len(p) &&
		p[0x11A] == byte(53) &&
		(p[0x11C] == DHCPOFFER ||
			p[0x11C] == DHCPACK ||
			p[0x11C] == DHCPNAK) {
		dhcpPacketCount.WithLabelValues(ethernet.SrcMAC.String()).Inc()
		log.Println("DHCP packet:", ethernet.SrcMAC.String())
	}

}
