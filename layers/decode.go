package layers

import "fmt"

type Decoder interface {
	// 对于字节数组进行解析，各种 协议需要自行实现
	Decode([]byte, PacketBuilder) error
}

type DecodeFunc func([]byte, PacketBuilder) error

func (d DecodeFunc) Decode(data []byte, p PacketBuilder) error {
	return d(data, p)
}

type Payload []byte

func (p Payload) String() string {
	return fmt.Sprintf("%-10s %d bytes", p.LayerType(), len(p))
}

func (p Payload) LayerType() LayerType {
	return LayerTypePayload
}

func (p Payload) LayerContents() []byte {
	return []byte(p)
}

func (p Payload) Payload() []byte {
	return []byte(p)
}

func (p Payload) LayerPayload() []byte {
	return nil
}

func (p *Payload) DecodeFromBytes(data []byte) error {
	*p = Payload(data)
	return nil
}

var DecodePayload Decoder = DecodeFunc(decodePayload)

// decodePayload decodes data by returning it all in a Payload layer.
func decodePayload(data []byte, p PacketBuilder) error {
	payload := &Payload{}
	if err := payload.DecodeFromBytes(data); err != nil {
		return err
	}
	p.AddLayer(payload)
	p.SetApplicationLayer(payload)
	return nil
}

type layerDecodingLayer interface {
	Layer
	DecodeFromBytes([]byte) error
	NextLayerType() LayerType
}

var LayerTypeZero = RegisterLayerType(0, LayerTypeMetadata{Name: "Unknown", Decoder: nil})

func decodingLayerDecoder(d layerDecodingLayer, data []byte, p PacketBuilder) error {
	err := d.DecodeFromBytes(data)
	if err != nil {
		return err
	}
	p.AddLayer(d)
	next := d.NextLayerType()
	if next == LayerTypeZero {
		return nil
	}
	return p.NextDecoder(next)
}
