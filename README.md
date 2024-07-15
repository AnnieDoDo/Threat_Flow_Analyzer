# BPF Topology Detector

## About The Project 
This project is to detect network topology by BPF. <br>
The detector would cover from L2 to L7 with different protocols. <br>

For example: Ethernet, IP, UDP, TCP, SSH, HTTP, HTTPs, ... and so on

## Built With

[linux BPF Documentation](https://docs.kernel.org/networking/filter.html)

## Getting Started
###  Write down your own low-level filter.

    The example is to exclude ssh, loop back from src and dst, and 0.0.0.1 from src and dst packets.
1. We can use tcpdump to generate the filter:
```
sudo tcpdump -i eth0 -dd 'tcp and not (port 22 or dst host 127.0.0.1 or dst host ::1 or src host 127.0.0.1 or src host ::1) and net 192.168.1.0/24'
```

2. Output:
```
{ 0x28, 0, 0, 0x0000000c },
{ 0x15, 20, 0, 0x000086dd },
{ 0x15, 0, 19, 0x00000800 },
{ 0x30, 0, 0, 0x00000017 },
{ 0x15, 0, 17, 0x00000006 },
{ 0x28, 0, 0, 0x00000014 },
{ 0x45, 5, 0, 0x00001fff },
{ 0xb1, 0, 0, 0x0000000e },
{ 0x48, 0, 0, 0x0000000e },
{ 0x15, 12, 0, 0x00000016 },
{ 0x48, 0, 0, 0x00000010 },
{ 0x15, 10, 0, 0x00000016 },
{ 0x20, 0, 0, 0x0000001e },
{ 0x15, 8, 0, 0x7f000001 },
{ 0x20, 0, 0, 0x0000001a },
{ 0x15, 6, 0, 0x7f000001 },
{ 0x54, 0, 0, 0xffffff00 },
{ 0x15, 3, 0, 0xc0a80100 },
{ 0x20, 0, 0, 0x0000001e },
{ 0x54, 0, 0, 0xffffff00 },
{ 0x15, 0, 1, 0xc0a80100 },
{ 0x6, 0, 0, 0x00040000 },
{ 0x6, 0, 0, 0x00000000 },
```

### Open the Promiscuous Mode and check:

    allows a network device to intercept and read each network packet that arrives in its entirety
Open:
```
sudo ifconfig eth0 -promisc
```

Check:
```
ifconfig eth0
```
Output:
```
eth0: flags=4419<UP,BROADCAST,RUNNING,PROMISC,MULTICAST>
```

### Copy into struct sock_filter code[] in bpf_gen_struct.h and compile:
```
gcc -o main main.c
```

## Usage
```
sudo ./main
```

## Roadmap
- [ ] Map to network header feild
  - [X] L2
    - [X] Ethernet
  - [ ] L3
    - [X] IP
    - [X] IPv6
    - [X] ARP
    - [x] IPv6 over IPv4
    - [ ] ICMP
  - [ ] L4
    - [ ] UDP
    - [ ] TCP
  - [ ] L7
    - [ ] SSH
    - [ ] HTTP
    - [ ] HTTPs
     
- [ ] How to store the IP information
  - [ ] database or file
  - [ ] what kind of format
     
- [ ] Add eBPF to do more actions.
  - [ ] Cross compile for RPi 4
  - [ ] Write my own eBPF like functions
      - [ ] Drop packets
      - [ ] Verify packets


