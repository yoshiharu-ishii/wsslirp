package slirpstack

import (
	"encoding/binary"
	"net"
	"net/netip"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

const leaseSeconds = 86400

// maybeHandleDHCP answers DHCP requests at the frame level, before the
// netstack sees them. Broadcast UDP handling inside netstack is subtle;
// answering here keeps the DHCP path deterministic and trivially testable.
func (ns *netstack) maybeHandleDHCP(frame []byte, fio FrameIO) bool {
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	req, ok := pkt.Layer(layers.LayerTypeDHCPv4).(*layers.DHCPv4)
	if !ok || req.Operation != layers.DHCPOpRequest {
		return false
	}
	var replyType layers.DHCPMsgType
	switch dhcpMsgType(req) {
	case layers.DHCPMsgTypeDiscover:
		replyType = layers.DHCPMsgTypeOffer
	case layers.DHCPMsgTypeRequest:
		replyType = layers.DHCPMsgTypeAck
	default:
		return true // ours to handle, nothing to say
	}
	reply, err := ns.buildDHCPReply(req, replyType)
	if err != nil {
		ns.cfg.Logf("dhcp: build reply: %v", err)
		return true
	}
	if err := fio.WriteFrame(reply); err != nil {
		ns.cfg.Logf("dhcp: write reply: %v", err)
	}
	ns.cfg.Logf("dhcp %s -> %s: %s leased to %s",
		dhcpMsgType(req), replyType, ns.cfg.GuestIP, req.ClientHWAddr)
	return true
}

// isArpForGuest reports whether frame is an ARP request asking about the
// guest's own IP (including RFC 5227 address-conflict probes with a zero
// sender). Nobody on a real LAN would answer those unless the address is
// actually taken, so the relay must stay silent too.
func (ns *netstack) isArpForGuest(frame []byte) bool {
	pkt := gopacket.NewPacket(frame, layers.LayerTypeEthernet, gopacket.Default)
	arp, ok := pkt.Layer(layers.LayerTypeARP).(*layers.ARP)
	if !ok || arp.Operation != layers.ARPRequest {
		return false
	}
	target, ok := netip.AddrFromSlice(arp.DstProtAddress)
	return ok && target == ns.cfg.GuestIP
}

func dhcpMsgType(d *layers.DHCPv4) layers.DHCPMsgType {
	for _, o := range d.Options {
		if o.Type == layers.DHCPOptMessageType && len(o.Data) == 1 {
			return layers.DHCPMsgType(o.Data[0])
		}
	}
	return layers.DHCPMsgTypeUnspecified
}

func (ns *netstack) buildDHCPReply(req *layers.DHCPv4, t layers.DHCPMsgType) ([]byte, error) {
	cfg := ns.cfg
	gw := net.IP(cfg.GatewayIP.AsSlice())
	mask := net.CIDRMask(cfg.PrefixLen, 32)
	lease := make([]byte, 4)
	binary.BigEndian.PutUint32(lease, leaseSeconds)

	eth := layers.Ethernet{
		SrcMAC:       cfg.GatewayMAC,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := layers.IPv4{
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolUDP,
		SrcIP:    gw,
		DstIP:    net.IPv4bcast,
	}
	udp := layers.UDP{SrcPort: 67, DstPort: 68}
	udp.SetNetworkLayerForChecksum(&ip)
	reply := layers.DHCPv4{
		Operation:    layers.DHCPOpReply,
		HardwareType: layers.LinkTypeEthernet,
		Xid:          req.Xid,
		Flags:        req.Flags,
		YourClientIP: net.IP(cfg.GuestIP.AsSlice()),
		NextServerIP: gw,
		ClientHWAddr: req.ClientHWAddr,
		Options: layers.DHCPOptions{
			layers.NewDHCPOption(layers.DHCPOptMessageType, []byte{byte(t)}),
			layers.NewDHCPOption(layers.DHCPOptServerID, gw.To4()),
			layers.NewDHCPOption(layers.DHCPOptLeaseTime, lease),
			layers.NewDHCPOption(layers.DHCPOptSubnetMask, mask),
			layers.NewDHCPOption(layers.DHCPOptRouter, gw.To4()),
			layers.NewDHCPOption(layers.DHCPOptDNS, net.IP(cfg.DNSIP.AsSlice()).To4()),
		},
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, &eth, &ip, &udp, &reply); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
