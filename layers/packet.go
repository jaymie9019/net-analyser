package layers

import (
	"bytes"
	"errors"
	"fmt"
	"time"
)

const ChinaDateFormat = "2006-01-02 15:04:05.000000"

// DataPacket 整个数据包
type DataPacket interface {
	// Metadata 数据包的元数据
	Metadata() *Metadata

	// Data 该数据包中的字节数据
	Data() []byte

	// Layers 该数据包中的所有分层的对象数组切片
	Layers() []Layer

	// LinkLayer 数据包中的各层数据
	LinkLayer() LinkLayer
	NetworkLayer() NetworkLayer
	TransportLayer() TransportLayer
	ApplicationLayer() ApplicationLayer

	// Layer 给定一个 LayerType 返回该层的对象
	Layer(LayerType) Layer

	String() string
	StartDecode(decoder Decoder)
}

type PacketBuilder interface {
	AddLayer(l Layer)

	SetLinkLayer(LinkLayer)
	SetNetworkLayer(NetworkLayer)
	SetTransportLayer(TransportLayer)
	SetApplicationLayer(ApplicationLayer)

	NextDecoder(next Decoder) error
}

// Metadata pcap 数数据包的基础接口
type Metadata struct {
	// Timestamp is the time the Packet was captured, if that is known.
	Timestamp time.Time
	CapLength int // 当前数据区的长度，即抓取到的数据帧长度
	Length    int // 离线数据长度，网路中实际数据帧的长度，一般不大于Caplen，多数情况下和Caplen值一样
}

func (m *Metadata) String() string {
	return fmt.Sprintf("%s  %d Bytes", m.Timestamp.Format(ChinaDateFormat), m.CapLength)
}

type Packet struct {
	data []byte

	metadata *Metadata

	layers []Layer
	last   Layer

	// 各个层
	link        LinkLayer
	network     NetworkLayer
	transport   TransportLayer
	application ApplicationLayer
}

// SimplePacket 对于 DataPacket 和 PacketBuilder 进行了简单的实现
type SimplePacket struct {
	Packet
}

func CreatePacket(Metadata *Metadata, data []byte, firstLayerDecoder Decoder) DataPacket {
	dataPacket := &SimplePacket{}
	dataPacket.metadata = Metadata
	dataPacket.data = data
	return dataPacket
}

func (p *Packet) StartDecode(dec Decoder) {
	_ = dec.Decode(p.data, p)
}

// 实现了 PacketBuilder

func (p *Packet) SetLinkLayer(l LinkLayer) {
	if l != nil {
		p.link = l
	}
}

func (p *Packet) SetNetworkLayer(l NetworkLayer) {
	if l != nil {
		p.network = l
	}
}

func (p *Packet) SetTransportLayer(l TransportLayer) {
	if l != nil {
		p.transport = l
	}
}

func (p *Packet) SetApplicationLayer(l ApplicationLayer) {
	if l != nil {
		p.application = l
	}
}

func (p *Packet) AddLayer(l Layer) {
	p.layers = append(p.layers, l)
	p.last = l
}

func (p *Packet) NextDecoder(next Decoder) error {
	if next == nil {
		return errors.New("NextDecoder passed nil decoder, probably an unsupported decode type")
	}
	if p.last == nil {
		return errors.New("NextDecoder called, but no layers added yet")
	}
	d := p.last.LayerPayload()
	if len(d) == 0 {
		return nil
	}
	// Since we're eager, immediately call the next decoder.
	return next.Decode(d, p)
}

// 实现了 DataPacket

func (p *Packet) Metadata() *Metadata {
	return p.metadata
}

func (p *Packet) Data() []byte {
	return p.data
}

func (p *Packet) Layers() []Layer {
	return p.layers
}

func (p *Packet) LinkLayer() LinkLayer {
	return p.link
}
func (p *Packet) NetworkLayer() NetworkLayer {
	return p.network
}
func (p *Packet) TransportLayer() TransportLayer {
	return p.transport
}
func (p *Packet) ApplicationLayer() ApplicationLayer {
	return p.application
}

func (p *Packet) Layer(t LayerType) Layer {
	for _, l := range p.layers {
		if l.LayerType() == t {
			return l
		}
	}
	return nil
}

func (p *Packet) String() string {
	var buff bytes.Buffer
	// 打印 数据包的头
	buff.WriteString(p.metadata.String())
	buff.WriteRune('\n')
	// 打印该数据包的每一层
	for i, layer := range p.Layers() {
		buff.WriteString(fmt.Sprintf("- Layer %d, %v\n", i+1, layer))
	}
	return buff.String()
}
