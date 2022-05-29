package layers

import (
	"encoding/binary"
	"fmt"
)

// UDP is the layer for UDP headers.
type UDP struct {
	BaseLayer
	SrcPort, DstPort UDPPort
	Length           uint16
	Checksum         uint16
	sPort, dPort     []byte
}

func (udp *UDP) String() string {
	return fmt.Sprintf("%-10s SrcPort: %s, DstPort: %s",
		udp.LayerType(), udp.SrcPort, udp.DstPort)
}

func (udp *UDP) LayerType() LayerType {
	return LayerTypeUDP
}

func (udp *UDP) DecodeFromBytes(data []byte) error {
	if len(data) < 8 {
		return fmt.Errorf("Invalid UDP header. Length %d less than 8", len(data))
	}
	udp.SrcPort = UDPPort(binary.BigEndian.Uint16(data[0:2]))
	udp.sPort = data[0:2]
	udp.DstPort = UDPPort(binary.BigEndian.Uint16(data[2:4]))
	udp.dPort = data[2:4]
	udp.Length = binary.BigEndian.Uint16(data[4:6])
	udp.Checksum = binary.BigEndian.Uint16(data[6:8])
	udp.BaseLayer = BaseLayer{Contents: data[:8]}
	switch {
	case udp.Length >= 8:
		hlen := int(udp.Length)
		if hlen > len(data) {
			hlen = len(data)
		}
		udp.Payload = data[8:hlen]
	case udp.Length == 0: // Jumbogram, use entire rest of data
		udp.Payload = data[8:]
	default:
		return fmt.Errorf("UDP Packet too small: %d bytes", udp.Length)
	}
	return nil
}

func (udp *UDP) NextLayerType() Decoder {
	// 如果目标端口是一些已知协议的端口，那么就按照对应协议解析
	if lt := udp.DstPort.LayerType(); lt != LayerTypePayload {
		return lt
	}
	// 否则就把这些数据变成应用层的数据
	return udp.SrcPort.LayerType()
}

func decodeUDP(data []byte, p PacketBuilder) error {
	udp := &UDP{}
	err := udp.DecodeFromBytes(data)
	p.AddLayer(udp)
	p.SetTransportLayer(udp)
	if err != nil {
		return err
	}
	return p.NextDecoder(udp.NextLayerType())
}
