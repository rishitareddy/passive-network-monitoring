package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	err     error
	timeout time.Duration = -1 * time.Second
	handle  *pcap.Handle
)

func main() {

	devices, _ := pcap.FindAllDevs()

	//Parse the command line arguments for i, r and s flags.
	interfacePtr := flag.String("i", devices[0].Name, "a string")
	filePtr := flag.String("r", "", "a string")
	stringPtr := flag.String("s", "", "a string")

	flag.Parse()

	var filter = flag.Args()

	// Open file to read from; else Read from device instead of file
	if *filePtr != "" {
		handle, err = pcap.OpenOffline(*filePtr)
		fmt.Println("Reading from file", *filePtr)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()
	} else if *interfacePtr != "" {
		fmt.Println("Reading from interface", *interfacePtr)
		handle, err = pcap.OpenLive(*interfacePtr, 65535, true, timeout)
		if err != nil {
			log.Fatal(err)
		}
		defer handle.Close()
	}

	//Set bpf filter based on argument passed (expression)
	if len(filter) > 0 {
		err = handle.SetBPFFilter(filter[0])
		if err != nil {
			log.Fatal(err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		//Declare all variables, and get timestamp and packet length from metadata

		var timestamp = packet.Metadata().Timestamp
		var srcMac = ""
		var destMac = ""
		var etherType = ""
		var length = packet.Metadata().CaptureInfo.Length
		var srcIP = ""
		var destIP = ""
		var srcPort = ""
		var destPort = ""
		var protocolType = ""
		var tcpFlags = ""
		var payload = ""
		var dnsID = ""

		//From ethernet layer, extract src mac, dest mac, ethernet type and payload
		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethernetLayer != nil {

			ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)

			srcMac = fmt.Sprintf("%s", ethernetPacket.SrcMAC)
			destMac = fmt.Sprintf("%s", ethernetPacket.DstMAC)
			var ether, _ = strconv.Atoi(fmt.Sprintf("%d", ethernetPacket.EthernetType))
			etherType = "0x" + fmt.Sprintf("%x", ether)

			payload = fmt.Sprintf("%s", ethernetPacket.Payload)

		}

		content := []byte(payload)

		if *stringPtr == "" || bytes.Contains(content, []byte(*stringPtr)) {

			//In IP layer, extract src ip, dest ip and protocol type
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer != nil {

				ip, _ := ipLayer.(*layers.IPv4)

				srcIP = fmt.Sprintf("%s", ip.SrcIP)
				destIP = fmt.Sprintf("%s", ip.DstIP)
				protocolType = fmt.Sprintf("%s", ip.Protocol)

			}

			dnsLayer := packet.Layer(layers.LayerTypeDNS)
			if dnsLayer != nil {

				dns, _ := dnsLayer.(*layers.DNS)

				// txIdval, _ := strconv.ParseUint(dns, 16, 16)

				dnsID = fmt.Sprintf("%s", dns.ID)

			}

			// If packet is TCP, extract src port, dest port and tcp flags
			tcpLayer := packet.Layer(layers.LayerTypeTCP)
			if tcpLayer != nil {

				tcp, _ := tcpLayer.(*layers.TCP)

				srcPort = fmt.Sprintf("%s", tcp.SrcPort)
				destPort = fmt.Sprintf("%s", tcp.DstPort)

				if tcp.FIN {
					tcpFlags += " FIN"
				}
				if tcp.SYN {
					tcpFlags += " SYN"
				}
				if tcp.RST {
					tcpFlags += " RST"
				}
				if tcp.PSH {
					tcpFlags += " PSH"
				}
				if tcp.ACK {
					tcpFlags += " ACK"
				}
				if tcp.URG {
					tcpFlags += " URG"
				}
				if tcp.ECE {
					tcpFlags += " ECE"
				}
				if tcp.CWR {
					tcpFlags += " CWR"
				}
				if tcp.NS {
					tcpFlags += " NS"
				}

			}

			// If packet is UDP, extract src port and dest port
			udpLayer := packet.Layer(layers.LayerTypeUDP)
			if udpLayer != nil {
				udp, _ := udpLayer.(*layers.UDP)
				srcPort = fmt.Sprintf("%s", udp.SrcPort)
				destPort = fmt.Sprintf("%s", udp.DstPort)
			}

			var reg, regerr = regexp.Compile("[^0-9]+")
			if regerr != nil {
				log.Fatal(regerr)
			}

			srcPort = reg.ReplaceAllString(srcPort, "")
			destPort = reg.ReplaceAllString(destPort, "")

			if strings.Contains(protocolType, "ICMP") {
				protocolType = "ICMP"
			}

			if protocolType != "TCP" && protocolType != "UDP" && protocolType != "ICMP" {
				protocolType = "OTHER"
			}

			//Format and print the parsed values
			fmt.Print(timestamp, " ")
			fmt.Print(srcMac, " -> ")
			fmt.Print(destMac, " ")
			fmt.Print("type ", etherType)
			fmt.Print(" len ", length)

			fmt.Print(" ", srcIP)
			if srcPort != "" {
				fmt.Print(":", srcPort)
			}
			if destIP != "" {
				fmt.Print(" -> ", destIP)
			}
			if destPort != "" {
				fmt.Print(":", destPort)
			}
			fmt.Print(" ", protocolType)
			fmt.Println(tcpFlags, " ")

			fmt.Println(dnsID, " ")

		}

	}
}
