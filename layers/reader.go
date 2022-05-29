package layers

import (
	"encoding/binary"
	"time"
)

type PacketReader struct {
	decoder   Decoder
	byteOrder binary.ByteOrder
	c         chan DataPacket
	readyChan chan DataPacket // 等待解析的数据包通道
	data      []byte
}

func (p *PacketReader) ReadPackets() chan DataPacket {
	j := 1
	for i := 0; i < len(p.data); {
		// 先解析元数据
		metadata := p.ReadPacketHeader(p.data[i : i+16])

		// 创建并且解析数据包
		dataPacket := CreatePacket(metadata, p.data[i+16:i+16+metadata.CapLength], p.decoder)
		dataPacket.StartDecode(p.decoder)
		//fmt.Println(j)
		//fmt.Println(dataPacket)
		//p.c <- dataPacket
		i += metadata.CapLength + 16
		j++
	}
	return p.c
}

// ReadPacketHeader 读取数据包的数据
func (p *PacketReader) ReadPacketHeader(data []byte) *Metadata {
	Metadata := &Metadata{}
	Metadata.Timestamp = time.Unix(int64(p.byteOrder.Uint32(data[0:4])), int64(p.byteOrder.Uint32(data[4:8])))
	Metadata.CapLength = int(p.byteOrder.Uint32(data[8:12]))
	Metadata.Length = int(p.byteOrder.Uint32(data[12:16]))
	return Metadata
}

func (p *PacketReader) readNext() (DataPacket, error) {
	dataPacket := &SimplePacket{}
	dataPacket.data = p.data
	dataPacket.Metadata()
	// 先解析元数据
	dataPacket.StartDecode(p.decoder)
	return dataPacket, nil
}
