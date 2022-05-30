
### 运行方法
cd 到对应的目录中 `cd /net-analyser/analyser/test1`

然后 build `go build -o main  main.go`  -o 后面的可执行文件名随意

如果要指定平台，比如说linux，参考这条

`CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o main main.go`


然后运行程序即可 

```bash
# 可以看到目当前目录下有一个 507M 的pcap
➜ ls -hl | grep pcap
-rw-r--r--  1 jaymie  staff   507M May 30 05:32 2.pcap
-rw-r--r--  1 jaymie  staff   527K May 23 17:24 day8.pcap


# 运行程序
➜ ./main 2.pcap
start working 2022-05-30 14:13:22.735373
start read and decode 2022-05-30 14:13:22.735561
unsupported EthernetType:  0
unsupported EthernetType:  0
finish read and decoding packets, total 1044794 packets, cost 1488 ms
write file:dns.txt  start at 2022-05-30 14:13:24.223840
write file:arp.txt  start at 2022-05-30 14:13:24.223918
write file:udp.txt  start at 2022-05-30 14:13:24.223927
write file:ip.txt  start at 2022-05-30 14:13:24.223874
write file:dns.txt end, cost: 64 ms
write file:arp.txt end, cost: 270 ms
write file:udp.txt end, cost: 1373 ms
write file:ip.txt end, cost: 4251 ms
cost: 5740 ms

# 查看输出结果
➜ ls -hl | grep txt                         
-rwxr-x--x  1 jaymie  staff    11M May 30 14:13 arp.txt
-rwxr-x--x  1 jaymie  staff   2.5M May 30 14:13 dns.txt
-rwxr-x--x  1 jaymie  staff   251M May 30 14:13 ip.txt
-rwxr-x--x  1 jaymie  staff    64M May 30 14:13 udp.txt

```