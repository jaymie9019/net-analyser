package layers

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

type PacketReader struct {
	decoder   Decoder
	byteOrder binary.ByteOrder
	c         chan DataPacket
	data      []byte
	Wg        sync.WaitGroup
	arpWg     sync.WaitGroup
	ipWg      sync.WaitGroup
	udpWg     sync.WaitGroup
	dnsWg     sync.WaitGroup
}

const (
	defaultBufSize = 4194304
	DateFormat     = "2006-01-02 15:04:05.000000"
)

var arpArray []DataPacket
var ippArray []DataPacket
var udpArray []DataPacket
var dnsArray []DataPacket

func (p *PacketReader) ReadPackets() chan DataPacket {
	start := time.Now()
	fmt.Printf("start read and decode %s\n", start.Format(ChinaDateFormat))
	j := 1

	for i := 0; i < len(p.data); {
		// 先解析元数据
		metadata := p.ReadPacketHeader(p.data[i : i+16])
		//p.Wg.Add(1)
		// 创建并且解析数据包
		dataPacket := CreatePacket(metadata, p.data[i+16:i+16+metadata.CapLength])

		//// 同步
		//dataPacket.StartDecode(p.decoder)
		//layer := dataPacket.Layer(LayerTypeARP)
		//if layer != nil {
		//	fmt.Println(dataPacket)
		//}

		// 异步
		//go p.decodePacket(dataPacket, arpWrite, ipWrite, udpWrite, dnsWrite)

		//go
		dataPacket.StartDecode(p.decoder)

		//p.decodePacket(dataPacket, arpFile, ipFile, udpFile, dnsFIle)

		lt := dataPacket.Layer(LayerTypeARP)
		if lt != nil {
			arpArray = append(arpArray, dataPacket)
		}

		lt = dataPacket.Layer(LayerTypeIPv4)
		if lt != nil {
			ippArray = append(ippArray, dataPacket)
		}

		lt = dataPacket.Layer(LayerTypeUDP)
		if lt != nil {
			udpArray = append(udpArray, dataPacket)
		}

		lt = dataPacket.Layer(LayerTypeDNS)
		if lt != nil {
			dnsArray = append(dnsArray, dataPacket)
		}

		i += metadata.CapLength + 16
		j++
	}
	fmt.Printf("finish read and decoding packets, total %d packets, cost %d ms\n", j, time.Since(start).Milliseconds())
	// 循环结束写文件
	p.Wg.Add(4)
	go p.writeFile("arp.txt", arpArray)
	go p.writeFile("ip.txt", ippArray)
	go p.writeFile("udp.txt", udpArray)
	go p.writeFile("dns.txt", dnsArray)

	p.Wg.Wait()
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

func (p *PacketReader) writeFile(filePath string, array []DataPacket) {
	start := time.Now()
	fmt.Printf("write file:%s  start at %s\n", filePath, start.Format(ChinaDateFormat))

	file, _ := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY, 0751)
	defer file.Close()
	writer := bufio.NewWriterSize(file, defaultBufSize)
	defer writer.Flush()

	for _, value := range array {
		content := value.String() + "\n"
		if writer.Available() < len([]byte(content)) {
			_ = writer.Flush()
		}
		_, _ = fmt.Fprintf(writer, content)
	}
	fmt.Printf("write file:%s end, cost: %d ms\n", filePath, time.Since(start).Milliseconds())
	p.Wg.Done()
}

//func (p *PacketReader) decodePacket(dataPacket DataPacket, arpWrite, ipWrite, udpWrite, dnsWrite *SafeFileWriter) {
//	dataPacket.StartDecode(p.decoder)
//
//	lt := dataPacket.Layer(LayerTypeARP)
//	if lt != nil {
//		p.arpWg.Add(1)
//		go p.write(dataPacket, arpWrite, LayerTypeARP)
//	}
//
//	lt = dataPacket.Layer(LayerTypeIPv4)
//	if lt != nil {
//		p.ipWg.Add(1)
//		go p.write(dataPacket, ipWrite, LayerTypeIPv4)
//	}
//
//	lt = dataPacket.Layer(LayerTypeUDP)
//	if lt != nil {
//		p.udpWg.Add(1)
//		go p.write(dataPacket, udpWrite, LayerTypeUDP)
//	}
//
//	lt = dataPacket.Layer(LayerTypeDNS)
//	if lt != nil {
//		p.dnsWg.Add(1)
//		go p.write(dataPacket, dnsWrite, LayerTypeDNS)
//	}
//	p.Wg.Done()
//}

func write(packet DataPacket, write *bufio.Writer) {
	if write.Available() < len([]byte(packet.String()+"\n")) {
		_ = write.Flush()
	}
}

//func (p *PacketReader) write(packet DataPacket, write *SafeFileWriter, lt LayerType) {
//	write.Lock.Lock()
//	defer write.Lock.Unlock()
//	if write.Writer.Available() < len([]byte(packet.String()+"\n")) {
//		_ = write.Writer.Flush()
//	}
//	_, _ = fmt.Fprintf(write.Writer, packet.String()+"\n")
//	switch lt {
//	case LayerTypeARP:
//		p.arpWg.Done()
//	case LayerTypeIPv4:
//		p.ipWg.Done()
//	case LayerTypeUDP:
//		p.udpWg.Done()
//	case LayerTypeDNS:
//		p.dnsWg.Done()
//	}
//}

type SafeFileWriter struct {
	Writer *bufio.Writer
	Lock   sync.Mutex
}

func NewWriterSize(w io.Writer, size int) *SafeFileWriter {
	Writer := bufio.NewWriterSize(w, size)
	return &SafeFileWriter{Writer, sync.Mutex{}}
}

func (p *PacketReader) decodePacket(dataPacket DataPacket, arpWrite, ipWrite, udpWrite, dnsWrite io.Writer) {
	dataPacket.StartDecode(p.decoder)
	//p.c <- dataPacket
	//
	//exists := dataPacket.Layer(LayerTypeARP)
	//if exists != nil {
	//	fmt.Fprintf(arpWrite, dataPacket.String()+"\n")
	//}
	//
	//exists = dataPacket.Layer(LayerTypeIPv4)
	//if exists != nil {
	//	fmt.Fprintf(ipWrite, dataPacket.String()+"\n")
	//}
	//
	//exists = dataPacket.Layer(LayerTypeUDP)
	//if exists != nil {
	//	fmt.Fprintf(udpWrite, dataPacket.String()+"\n")
	//}
	//
	//exists = dataPacket.Layer(LayerTypeDNS)
	//if exists != nil {
	//	fmt.Fprintf(dnsWrite, dataPacket.String()+"\n")
	//}
	//p.Wg.Done()
}
