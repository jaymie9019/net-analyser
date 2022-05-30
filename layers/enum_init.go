package layers

import (
	"fmt"
	"strconv"
)

// 模块加载的时候初始化各种枚举类型
func init() {
	LinkTypeMetadata = make(map[LinkType]EnumMetadata)
	EthernetTypeMetadata = make(map[EthernetType]EnumMetadata)
	IPProtocolMetadata = make(map[IPProtocol]EnumMetadata)

	// 链路层类型
	LinkTypeMetadata[LinkTypeEthernet] = EnumMetadata{DecodeWith: DecodeFunc(decodeEthernet), Name: "Ethernet"}

	// 以太网
	EthernetTypeMetadata[EthernetTypeIPv4] = EnumMetadata{DecodeWith: DecodeFunc(decodeIPv4), Name: "IPv4", LayerType: LayerTypeIPv4}
	EthernetTypeMetadata[EthernetTypeARP] = EnumMetadata{DecodeWith: DecodeFunc(decodeARP), Name: "ARP", LayerType: LayerTypeARP}

	IPProtocolMetadata[IPProtocolTCP] = EnumMetadata{DecodeWith: DecodeFunc(decodeTCP), Name: "TCP", LayerType: LayerTypeTCP}
	IPProtocolMetadata[IPProtocolUDP] = EnumMetadata{DecodeWith: DecodeFunc(decodeUDP), Name: "UDP", LayerType: LayerTypeUDP}

}

// LinkTypeMetadata
var LinkTypeMetadata map[LinkType]EnumMetadata

func (lt LinkType) Decode(data []byte, p PacketBuilder) error {
	return LinkTypeMetadata[lt].DecodeWith.Decode(data, p)
}

// EthernetTypeMetadata
var EthernetTypeMetadata map[EthernetType]EnumMetadata

func (a EthernetType) Decode(data []byte, p PacketBuilder) error {
	if metadata, ok := EthernetTypeMetadata[a]; ok {
		return metadata.DecodeWith.Decode(data, p)
	}
	fmt.Println("unsupported EthernetType: ", strconv.Itoa(int(a)))
	return nil
}

func (a EthernetType) String() string {
	if metadata, ok := EthernetTypeMetadata[a]; ok {
		return metadata.Name
	}
	return "unsupported EthernetType: " + strconv.Itoa(int(a))
}

var IPProtocolMetadata map[IPProtocol]EnumMetadata

// Decoder calls IPProtocolMetadata.DecodeWith's decoder.
func (a IPProtocol) Decode(data []byte, p PacketBuilder) error {
	return IPProtocolMetadata[a].DecodeWith.Decode(data, p)
}

// String returns IPProtocolMetadata.Name.
func (a IPProtocol) String() string {
	return IPProtocolMetadata[a].Name
}

// LayerType returns IPProtocolMetadata.LayerType.
func (a IPProtocol) LayerType() LayerType {
	if metadata, ok := IPProtocolMetadata[a]; ok {
		return metadata.LayerType
	}
	return UnknownLayer
}
