package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

type Ethernet struct {
	BaseLayer
	SrcMAC, DstMAC net.HardwareAddr
	EthernetType   EthernetType
	Length         uint16
}

func (eth *Ethernet) String() string {
	return fmt.Sprintf("%-10s srcMac: %v, dstMac: %v, EthernetType:%s",
		eth.LayerType(), eth.SrcMAC, eth.DstMAC, eth.EthernetType)
}

func (eth *Ethernet) LayerType() LayerType {
	return LayerTypeEthernet
}

func (eth *Ethernet) DecodeFromBytes(data []byte) error {
	if len(data) < 14 {
		return errors.New("ethernet Packet too small")
	}
	eth.DstMAC = net.HardwareAddr(data[0:6])
	eth.SrcMAC = net.HardwareAddr(data[6:12])
	eth.EthernetType = EthernetType(binary.BigEndian.Uint16(data[12:14]))
	eth.BaseLayer = BaseLayer{data[:14], data[14:]}
	eth.Length = 0
	if eth.EthernetType < 0x0600 {
		eth.Length = uint16(eth.EthernetType)
		eth.EthernetType = EthernetTypeLLC
		if cmp := len(eth.Payload) - int(eth.Length); cmp < 0 {
			//df.SetTruncated()
		} else if cmp > 0 {
			// Strip off bytes at the end, since we have too many bytes
			eth.Payload = eth.Payload[:len(eth.Payload)-cmp]
		}
	}
	return nil
}

func decodeEthernet(data []byte, p PacketBuilder) error {
	eth := &Ethernet{}
	err := eth.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	p.AddLayer(eth)
	p.SetLinkLayer(eth)
	return p.NextDecoder(eth.EthernetType)
}
