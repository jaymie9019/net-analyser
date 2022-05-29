package layers

import "errors"

type LayerType int

var (
	UnknownLayer = RegisterLayerType(0, LayerTypeMetadata{"UnknownLayer", nil})

	LayerTypeARP = RegisterLayerType(10, LayerTypeMetadata{Name: "ARP", Decoder: DecodeFunc(decodeARP)})

	LayerTypeEthernet = RegisterLayerType(17, LayerTypeMetadata{"Ethernet", DecodeFunc(decodeEthernet)})
	LayerTypeIPv4     = RegisterLayerType(20, LayerTypeMetadata{"IPv4", DecodeFunc(decodeIPv4)})
	LayerTypeTCP      = RegisterLayerType(44, LayerTypeMetadata{Name: "TCP", Decoder: DecodeFunc(decodeTCP)})
	LayerTypeUDP      = RegisterLayerType(45, LayerTypeMetadata{Name: "UDP", Decoder: DecodeFunc(decodeUDP)})

	LayerTypeDNS = RegisterLayerType(107, LayerTypeMetadata{Name: "DNS", Decoder: DecodeFunc(decodeDNS)})

	// todo: 暂时都不实现
	LayerTypeNTP    LayerType = RegisterLayerType(0, LayerTypeMetadata{"UnknownLayer", nil})
	LayerTypeVXLAN  LayerType = RegisterLayerType(0, LayerTypeMetadata{"UnknownLayer", nil})
	LayerTypeDHCPv4 LayerType = RegisterLayerType(0, LayerTypeMetadata{"UnknownLayer", nil})
	LayerTypeDHCPv6 LayerType = RegisterLayerType(0, LayerTypeMetadata{"UnknownLayer", nil})
	LayerTypeSIP    LayerType = RegisterLayerType(0, LayerTypeMetadata{"UnknownLayer", nil})
	LayerTypeSFlow  LayerType = RegisterLayerType(0, LayerTypeMetadata{"UnknownLayer", nil})
	LayerTypeGeneve LayerType = RegisterLayerType(0, LayerTypeMetadata{"UnknownLayer", nil})
	LayerTypeBFD    LayerType = RegisterLayerType(0, LayerTypeMetadata{"UnknownLayer", nil})
	LayerTypeGTPv1U LayerType = RegisterLayerType(0, LayerTypeMetadata{"UnknownLayer", nil})
	LayerTypeRMCP   LayerType = RegisterLayerType(0, LayerTypeMetadata{"UnknownLayer", nil})
	LayerTypeRADIUS LayerType = RegisterLayerType(0, LayerTypeMetadata{"UnknownLayer", nil})

	LayerTypePayload = RegisterLayerType(2, LayerTypeMetadata{Name: "Payload", Decoder: DecodePayload})
)

// LayerTypeMetadata contains metadata associated with each LayerType.
type LayerTypeMetadata struct {
	Name    string
	Decoder Decoder
}

var ltMetaMap = map[LayerType]LayerTypeMetadata{}

func RegisterLayerType(num int, meta LayerTypeMetadata) LayerType {
	ltMetaMap[LayerType(num)] = meta
	return LayerType(num)
}

func (l LayerType) String() string {
	return ltMetaMap[l].Name
}

func (l LayerType) Decode(bytes []byte, builder PacketBuilder) error {
	if l == UnknownLayer {
		return errors.New("unknown layer type")
	}
	return ltMetaMap[l].Decoder.Decode(bytes, builder)
}
