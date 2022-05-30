package layers

// LinkType 链路层协议类型
type LinkType uint8

const (
	// According to pcap-linktype(7) and http://www.tcpdump.org/linktypes.html
	LinkTypeNull           LinkType = 0
	LinkTypeEthernet       LinkType = 1
	LinkTypeAX25           LinkType = 3
	LinkTypeTokenRing      LinkType = 6
	LinkTypeArcNet         LinkType = 7
	LinkTypeSLIP           LinkType = 8
	LinkTypePPP            LinkType = 9
	LinkTypeFDDI           LinkType = 10
	LinkTypePPP_HDLC       LinkType = 50
	LinkTypePPPEthernet    LinkType = 51
	LinkTypeATM_RFC1483    LinkType = 100
	LinkTypeRaw            LinkType = 101
	LinkTypeC_HDLC         LinkType = 104
	LinkTypeIEEE802_11     LinkType = 105
	LinkTypeFRelay         LinkType = 107
	LinkTypeLoop           LinkType = 108
	LinkTypeLinuxSLL       LinkType = 113
	LinkTypeLTalk          LinkType = 114
	LinkTypePFLog          LinkType = 117
	LinkTypePrismHeader    LinkType = 119
	LinkTypeIPOverFC       LinkType = 122
	LinkTypeSunATM         LinkType = 123
	LinkTypeIEEE80211Radio LinkType = 127
	LinkTypeARCNetLinux    LinkType = 129
	LinkTypeIPOver1394     LinkType = 138
	LinkTypeMTP2Phdr       LinkType = 139
	LinkTypeMTP2           LinkType = 140
	LinkTypeMTP3           LinkType = 141
	LinkTypeSCCP           LinkType = 142
	LinkTypeDOCSIS         LinkType = 143
	LinkTypeLinuxIRDA      LinkType = 144
	LinkTypeLinuxLAPD      LinkType = 177
	LinkTypeLinuxUSB       LinkType = 220
	LinkTypeFC2            LinkType = 224
	LinkTypeFC2Framed      LinkType = 225
	LinkTypeIPv4           LinkType = 228
	LinkTypeIPv6           LinkType = 229
)

// EnumMetadata keeps track of a set of metadata for each enumeration value
// for protocol enumerations.
type EnumMetadata struct {
	// DecodeWith is the decoder to use to decode this protocol's data.
	DecodeWith Decoder
	// Name is the name of the enumeration value.
	Name string
	// LayerType is the layer type implied by the given enum.
	LayerType LayerType
}

// EthernetType 以太网协议的上层协议类型
type EthernetType uint16

const (
	EthernetTypeLLC                         EthernetType = 0
	EthernetTypeIPv4                        EthernetType = 0x0800
	EthernetTypeARP                         EthernetType = 0x0806
	EthernetTypeIPv6                        EthernetType = 0x86DD
	EthernetTypeCiscoDiscovery              EthernetType = 0x2000
	EthernetTypeNortelDiscovery             EthernetType = 0x01a2
	EthernetTypeTransparentEthernetBridging EthernetType = 0x6558
	EthernetTypeDot1Q                       EthernetType = 0x8100
	EthernetTypePPP                         EthernetType = 0x880b
	EthernetTypePPPoEDiscovery              EthernetType = 0x8863
	EthernetTypePPPoESession                EthernetType = 0x8864
	EthernetTypeMPLSUnicast                 EthernetType = 0x8847
	EthernetTypeMPLSMulticast               EthernetType = 0x8848
	EthernetTypeEAPOL                       EthernetType = 0x888e
	EthernetTypeERSPAN                      EthernetType = 0x88be
	EthernetTypeQinQ                        EthernetType = 0x88a8
	EthernetTypeLinkLayerDiscovery          EthernetType = 0x88cc
	EthernetTypeEthernetCTP                 EthernetType = 0x9000
)

// IP 协议的上层协议

type IPProtocol uint8

const (
	IPProtocolIPv6HopByHop    IPProtocol = 0
	IPProtocolICMPv4          IPProtocol = 1
	IPProtocolIGMP            IPProtocol = 2
	IPProtocolIPv4            IPProtocol = 4
	IPProtocolTCP             IPProtocol = 6
	IPProtocolUDP             IPProtocol = 17
	IPProtocolRUDP            IPProtocol = 27
	IPProtocolIPv6            IPProtocol = 41
	IPProtocolIPv6Routing     IPProtocol = 43
	IPProtocolIPv6Fragment    IPProtocol = 44
	IPProtocolGRE             IPProtocol = 47
	IPProtocolESP             IPProtocol = 50
	IPProtocolAH              IPProtocol = 51
	IPProtocolICMPv6          IPProtocol = 58
	IPProtocolNoNextHeader    IPProtocol = 59
	IPProtocolIPv6Destination IPProtocol = 60
	IPProtocolOSPF            IPProtocol = 89
	IPProtocolIPIP            IPProtocol = 94
	IPProtocolEtherIP         IPProtocol = 97
	IPProtocolVRRP            IPProtocol = 112
	IPProtocolSCTP            IPProtocol = 132
	IPProtocolUDPLite         IPProtocol = 136
	IPProtocolMPLSInIP        IPProtocol = 137
)
