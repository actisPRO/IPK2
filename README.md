![BUT FIT logo](https://wis.fit.vutbr.cz/images/fitnewben.png)

# Computer Communications and Networks - Project #2

**Author**: Denis Karev ([xkarev00@stud.fit.vutbr.cz](mailto:xkarev00@stud.fit.vutbr.cz))

**This project should not be used for non-educational purposes.**


## Description

A simple packet sniffer, which can catch TCP, UDP, ARP and ICMP packets sent 
or received on the specific network adapter.

## Build
The provided Makefile will build the application from the source.
The path to the output DLL file is `bin\Release\netcoreapp3.1\IPK2.Zeta.dll`
```shell
make
```

## Run
Run using the following command:
```shell
./ipk-sniffer [-i | --interface ] {-p port} {[--tcp|-t] [--udp|-u] [--arp] [--icmp] } {-n num}
```
where:
* `-i` or `--interface` sets the network interface name to sniff packets on.
  If not set, the program will print the list of available interfaces and exit.
* `-p` – sets the port number to be monitored. It includes both, source and
  destination ports. If not set, the program will monitor all the ports.
* `-t` or `--tcp` – if set, program will monitor TCP packets.
* `-u` or `--udp` – if set, program will monitor TCP packets.
* `--icmp` – if set, program will monitor ICMP packets.
* `--arp` – if set, program will monitor ARP packets.
* `-n` is an amount of packets to sniff, defaults to 1.

## Usage

Packet data is printed in the following format:
```
timestamp: [RFC3339 timestamp]
src MAC: [source hardware address]
dst MAC: [destination hardware address]
frame length: [length of the packet in bytes]
src IP: [if exists, source IP address]
dst IP: [if exists, destination IP address]
src port: [if exists, source port]
dst port: [if exists, destination port]

[HEX byte offset]: [up to 16 HEX byte values] [up to 16 byte ASCII value (or . if unprintable)]
```

## Files

* `IPK2.Zeta.csproj` - project file.
* `IPK2.Zeta.sln` - solution file.
* `ipk-sniffer` - start-up Shell script.
* `Makefile`
* `manual.pdf` - documentation.
* `PacketData.cs` - class used for storing packet data.
* `Program.cs` - executable class.
* `Settings.cs` - structure used for storing settings.
* `Sniffer.cs`- class used for sniffing packets.
* `README.md` - short documentation.
