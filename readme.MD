#Description

Packet analyser application works just like Wireshark.This application can't capture the package.
It analyses a captured packet.It will extract and display the different headers of the captured packets in the file datafile. First, it displays the ethernet header fields of the captured frames. Second, if the ethernet frame contains an IP datagram, it prints the IP header. Third, it prints the packets encapsulated in the IP datagram. TCP, UDP, or ICMP packets can be encapsulated in the IP packet.

It works as a shell command along with the packet captured file.

##How to Use

```commandline
chmod +x pktanalyzer.sh

```
This command makes the shell script executable. The shell script executes the packet analyser application.

```bash
./pktanalyzer.sh tcp.bin
```
```bash
./pktanalyzer.sh udp.bin
```
```bash
./pktanalyzer.sh icmp.bin
```
 One sample response is as follows:
 
```

ETHER : -----Ether header-----
ETHER :
ETHER: Destination MAC = 00:00:0c:07:ac:01
ETHER: Source MAC = c0:14:3d:d5:72:8b
ETHER: EtherType = 0800 (IP)
ETHER :

IP : -----IP header-----
IP :
IP: Version = 4
IP: Header length = 20 bytes
IP: Type of service = 0x0
IP:      xxx. .... = 000 ( precedence )
IP:      ...0 .... = normal  delay
IP:      .... 0... = normal throughput
IP:      .... .0.. = normal reliability
IP: Total length = 252 bytes
IP: Identification = 7eec ( 32492 )
IP: Flags = 0x4
IP:      0... .... = reserve flag
IP:      .1... .... = do not fragment
IP:      ..0. .... = last fragment
IP: Fragment Offset = 0 bytes
IP: Time to live = 64 seconds/hops
IP: Protocol Field = 6
IP: Header Checksum = 4a9e
IP: Source IP = 129.21.66.85 , Unknown host
IP: Destination IP = 172.217.0.46 , lga15s43-in-f14.1e100.net
IP :

TCP : -----TCP header-----
TCP :
TCP: Source Port = 52566
TCP: Destination Port = 443
TCP: Sequence Number = 424114169
TCP: ACK = 2974881950
TCP: Data Offset = 32 bytes
TCP: Reserved = 000
TCP: Nonce = 0
TCP: CWR = 0
TCP: ECN = 0
TCP : Flags = 0x18
TCP:     ..0. .... = No urgent pointer
TCP:     ...1 .... = Acknowledgement
TCP:     .... 1... = Push
TCP:     .... .0.. = No reset
TCP:     .... ..0. = No Syn
TCP:     .... ...0 = No fin
TCP: Window = 1832
TCP: Checksum = 75b0
TCP: Urgent = 0000
TCP: DATA = 0101080a0007eb7b5410dc4817030300c300000000000000713efc3bb6cefab367919e87b9ac681c2696dc87a4e28f7cbbb2adb3bda33fbf37b2e19a9d8ca5b08ca559bd9ebf2f98558f9cad93ffc367993afc80c8c9ea6638fb972ff947f398409a4e6d5df5b9c83a9ddfe6068e4208ccc358cf34efe5655ae92baaf9fce57fc562a57ff6104ddb9b3d04ea564f1630054e7191d120c8823e21a0b93f7a4893c5a476f494d6a89d8fd8859623469aeea1ff33579855a0b330b029052cf657197a1744838229e8aa81f4c4b29391a69f6b8aed17```
```
