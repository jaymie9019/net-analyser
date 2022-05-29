package layers

import (
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"os"
	"strings"
)

func mmapRead(filePath string) ([]byte, error) {
	file, err := os.OpenFile(filePath, os.O_RDWR, 0644)
	if err != nil {
		fmt.Println("open file failed, error", err)
		return nil, err
	}
	state, _ := file.Stat()

	data, err := unix.Mmap(int(file.Fd()), 0, int(state.Size()), unix.PROT_READ, unix.MAP_SHARED)
	if err != nil {
		fmt.Println("mmap error: ", err)
		return nil, err
	}
	return data, nil
}

func CreatePacketReaderFromFile(filePath string) (*PacketReader, error) {
	if !strings.HasSuffix(filePath, "pcap") {
		return nil, errors.New("file suffix should be pcap")
	}

	bytes, err := mmapRead(filePath)
	if err != nil {
		return nil, errors.New("read file failed, error: " + err.Error())
	}

	if len(bytes) < 24 {
		return nil, errors.New("error data")
	}

	// 先读取出 Pcap 的 header
	pcapHeader, byteOrder := readPcapHeader(bytes[:24])

	return &PacketReader{
		pcapHeader.LinkType,
		byteOrder,
		make(chan DataPacket, 200),
		// 去掉 pcap header 的 24 个字节
		bytes[24:],
	}, nil
}

func readPcapHeader(data []byte) (*PcapHeader, binary.ByteOrder) {
	PcapHeader := &PcapHeader{}
	PcapHeader.Magic = binary.BigEndian.Uint32(data[:4]) // Magic
	var byteOrder binary.ByteOrder

	switch PcapHeader.Magic {
	// 大端
	case 0xa1b2c3d4:
		byteOrder = binary.BigEndian
	// 小端
	case 0xd4c3b2a1:
		byteOrder = binary.LittleEndian
	case 0x4d3cb2a1:
		byteOrder = binary.LittleEndian
	}

	PcapHeader.Major = byteOrder.Uint16(data[4:6])
	PcapHeader.Minor = byteOrder.Uint16(data[6:8])
	PcapHeader.ThisZone = byteOrder.Uint32(data[8:12])
	PcapHeader.SigFigs = byteOrder.Uint32(data[12:16])
	PcapHeader.SnapLen = byteOrder.Uint32(data[16:20])
	PcapHeader.LinkType = LinkType(byteOrder.Uint32(data[20:]))
	return PcapHeader, byteOrder
}

type PcapHeader struct {
	Magic     uint32 // 0xa1b2c3d4表示是大端模式 0xd4c3b2a1表示小端模式
	Major     uint16
	Minor     uint16
	ThisZone  uint32
	SigFigs   uint32
	SnapLen   uint32
	LinkType  LinkType // 链路类型
	ByteOrder binary.ByteOrder
}
