package main

import (
	"fmt"
	"net-analyser/layers"
	"os"
	"time"
)

func main() {
	// 单线程 230M 270ms
	// 单线程 500M  不写文件 cost: 3295 ms  写文件 8-10秒
	// 写文件并发 9-10秒
	start := time.Now()
	fmt.Printf("start working %s\n", start.Format(layers.ChinaDateFormat))

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "no filePath parameters")
	}
	filePath := os.Args[1:2][0]

	//filePath := "examples/test1/2.pcap"
	reader, err := layers.CreatePacketReaderFromFile(filePath)
	if err != nil {
		fmt.Println(err)
	}

	//i := 1
	_ = reader.ReadPackets()

	fmt.Printf("cost: %d ms\n", time.Since(start).Milliseconds())

}
