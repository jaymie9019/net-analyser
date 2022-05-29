package main

import (
	"fmt"
	"net-analyser/layers"
	"time"
)

func main() {
	//filePath := "test/test1/day8.pcap"
	// 单线程 230M 0.277288  cost: 0.263168
	start := time.Now()

	filePath := "test/test1/3.pcap"
	reader, err := layers.CreatePacketReaderFromFile(filePath)
	if err != nil {
		fmt.Println(err)
	}

	//i := 1
	reader.ReadPackets()

	fmt.Printf("cost: %d ms", time.Since(start).Milliseconds())

}
