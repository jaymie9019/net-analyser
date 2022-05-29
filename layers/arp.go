package layers

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

const (
	ARPRequest = 1
	ARPReply   = 2
)

// ARP is a ARP packet header.
type ARP struct {
	BaseLayer
	AddrType          LinkType
	Protocol          EthernetType
	HwAddressSize     uint8
	ProtAddressSize   uint8
	Operation         uint16
	SourceHwAddress   net.HardwareAddr
	SourceProtAddress net.IP
	DstHwAddress      net.HardwareAddr
	DstProtAddress    net.IP
}

func (arp *ARP) String() string {
	var buff bytes.Buffer
	buff.WriteString(fmt.Sprintf("%-10s %s: ", arp.LayerType(), arp.getOperation()))
	if arp.Operation == ARPRequest {
		buff.WriteString(fmt.Sprintf("Who has %s? Tell %s(%s)", arp.DstProtAddress, arp.SourceProtAddress, arp.SourceHwAddress))
	} else if arp.Operation == ARPReply {
		buff.WriteString(fmt.Sprintf("hi %s(%s), tell you %s is at %s",
			arp.SourceProtAddress, arp.SourceHwAddress, arp.DstProtAddress, arp.DstHwAddress))
	}

	return buff.String()

}

func (arp *ARP) getOperation() string {
	if arp.Operation == ARPRequest {
		return "request"
	} else if arp.Operation == ARPReply {
		return "response"
	}
	return ""
}

func (arp *ARP) DecodeFromBytes(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("ARP length %d too short", len(data))
	}
	arp.AddrType = LinkType(binary.BigEndian.Uint16(data[0:2]))
	arp.Protocol = EthernetType(binary.BigEndian.Uint16(data[2:4]))
	arp.HwAddressSize = data[4]
	arp.ProtAddressSize = data[5]

	arp.Operation = binary.BigEndian.Uint16(data[6:8])

	arpLength := 8 + 2*arp.HwAddressSize + 2*arp.ProtAddressSize
	if len(data) < int(arpLength) {
		return fmt.Errorf("ARP length %d too short, %d expected", len(data), arpLength)
	}
	arp.SourceHwAddress = data[8 : 8+arp.HwAddressSize]
	arp.SourceProtAddress = data[8+arp.HwAddressSize : 8+arp.HwAddressSize+arp.ProtAddressSize]
	arp.DstHwAddress = data[8+arp.HwAddressSize+arp.ProtAddressSize : 8+2*arp.HwAddressSize+arp.ProtAddressSize]
	arp.DstProtAddress = data[8+2*arp.HwAddressSize+arp.ProtAddressSize : 8+2*arp.HwAddressSize+2*arp.ProtAddressSize]

	arp.Contents = data[:arpLength]
	arp.Payload = data[arpLength:]
	return nil
}

func (arp *ARP) NextLayerType() LayerType {
	return LayerTypePayload
}

func (arp *ARP) LayerType() LayerType { return LayerTypeARP }

func decodeARP(data []byte, p PacketBuilder) error {
	arp := &ARP{}
	return decodingLayerDecoder(arp, data, p)
}
