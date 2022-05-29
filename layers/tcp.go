package layers

import "fmt"

// TCP is the layer for TCP headers.
type TCP struct {
	BaseLayer
}

func (tcp *TCP) LayerType() LayerType {
	return LayerTypeTCP
}

func (tcp *TCP) String() string {
	return fmt.Sprintf("%-10s", tcp.LayerType())
}

func (tcp *TCP) DecodeFromBytes(data []byte) error {
	// todo: implement
	return nil
}

func decodeTCP(data []byte, p PacketBuilder) error {
	tcp := &TCP{}
	//err := tcp.DecodeFromBytes(data, p)
	p.AddLayer(tcp)
	p.SetTransportLayer(tcp)
	return nil
}
