package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
)

type IPv4Flag uint8

const (
	IPv4EvilBit       IPv4Flag = 1 << 2 // http://tools.ietf.org/html/rfc3514 ;)
	IPv4DontFragment  IPv4Flag = 1 << 1
	IPv4MoreFragments IPv4Flag = 1 << 0
)

func (f IPv4Flag) String() string {
	var s []string
	if f&IPv4EvilBit != 0 {
		s = append(s, "Evil")
	}
	if f&IPv4DontFragment != 0 {
		s = append(s, "DF")
	}
	if f&IPv4MoreFragments != 0 {
		s = append(s, "MF")
	}
	return strings.Join(s, "|")
}

type IPv4Option struct {
	OptionType   uint8
	OptionLength uint8
	OptionData   []byte
}

// IPv4 is the header of an IP Packet.
type IPv4 struct {
	BaseLayer
	Version    uint8
	IHL        uint8
	TOS        uint8
	Length     uint16
	Id         uint16
	Flags      IPv4Flag
	FragOffset uint16
	TTL        uint8
	Protocol   IPProtocol
	Checksum   uint16
	SrcIP      net.IP
	DstIP      net.IP
	Options    []IPv4Option
	Padding    []byte
}

func (ip *IPv4) LayerType() LayerType {
	return LayerTypeIPv4
}

func (ip *IPv4) String() string {
	return fmt.Sprintf("%-10s Version: %d, SrcIP: %s, DstIP: %s, Protocol: %s",
		ip.LayerType(), ip.Version, ip.SrcIP, ip.DstIP, ip.Protocol.LayerType())
}

func (ip *IPv4) DecodeFromBytes(data []byte) error {
	if len(data) < 20 {
		return fmt.Errorf("Invalid ip4 header. Length %d less than 20", len(data))
	}
	flagsfrags := binary.BigEndian.Uint16(data[6:8])

	ip.Version = uint8(data[0]) >> 4
	ip.IHL = uint8(data[0]) & 0x0F
	ip.TOS = data[1]
	ip.Length = binary.BigEndian.Uint16(data[2:4])
	ip.Id = binary.BigEndian.Uint16(data[4:6])
	ip.Flags = IPv4Flag(flagsfrags >> 13)
	ip.FragOffset = flagsfrags & 0x1FFF
	ip.TTL = data[8]
	ip.Protocol = IPProtocol(data[9])
	ip.Checksum = binary.BigEndian.Uint16(data[10:12])
	ip.SrcIP = data[12:16]
	ip.DstIP = data[16:20]
	ip.Options = ip.Options[:0]
	ip.Padding = nil
	// Set up an initial guess for contents/payload... we'll reset these soon.
	ip.BaseLayer = BaseLayer{Contents: data}

	if ip.Length < 20 {
		return fmt.Errorf("Invalid (too small) IP length (%d < 20)", ip.Length)
	} else if ip.IHL < 5 {
		return fmt.Errorf("Invalid (too small) IP header length (%d < 5)", ip.IHL)
	} else if int(ip.IHL*4) > int(ip.Length) {
		return fmt.Errorf("Invalid IP header length > IP length (%d > %d)", ip.IHL, ip.Length)
	}
	if cmp := len(data) - int(ip.Length); cmp > 0 {
		data = data[:ip.Length]
	} else if cmp < 0 {
		if int(ip.IHL)*4 > len(data) {
			return errors.New("Not all IP header bytes available")
		}
	}
	ip.Contents = data[:ip.IHL*4]
	ip.Payload = data[ip.IHL*4:]
	// From here on, data contains the header options.
	data = data[20 : ip.IHL*4]
	// Pull out IP options
	for len(data) > 0 {
		if ip.Options == nil {
			// Pre-allocate to avoid growing the slice too much.
			ip.Options = make([]IPv4Option, 0, 4)
		}
		opt := IPv4Option{OptionType: data[0]}
		switch opt.OptionType {
		case 0: // End of options
			opt.OptionLength = 1
			ip.Options = append(ip.Options, opt)
			ip.Padding = data[1:]
			return nil
		case 1: // 1 byte padding
			opt.OptionLength = 1
			data = data[1:]
			ip.Options = append(ip.Options, opt)
		default:
			if len(data) < 2 {
				return fmt.Errorf("Invalid ip4 option length. Length %d less than 2", len(data))
			}
			opt.OptionLength = data[1]
			if len(data) < int(opt.OptionLength) {
				return fmt.Errorf("IP option length exceeds remaining IP header size, option type %v length %v", opt.OptionType, opt.OptionLength)
			}
			if opt.OptionLength <= 2 {
				return fmt.Errorf("Invalid IP option type %v length %d. Must be greater than 2", opt.OptionType, opt.OptionLength)
			}
			opt.OptionData = data[2:opt.OptionLength]
			data = data[opt.OptionLength:]
			ip.Options = append(ip.Options, opt)
		}
	}
	return nil
}

func (ip *IPv4) NextLayerType() LayerType {
	return ip.Protocol.LayerType()
}

func decodeIPv4(data []byte, p PacketBuilder) error {
	ip := &IPv4{}
	err := ip.DecodeFromBytes(data)
	p.AddLayer(ip)
	p.SetNetworkLayer(ip)
	if err != nil {
		return err
	}
	return p.NextDecoder(ip.NextLayerType())
}
