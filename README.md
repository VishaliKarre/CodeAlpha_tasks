# CodeAlpha_NetworkSniffer

**CodeAlpha Cybersecurity Internship — Task 1: Basic Network Sniffer**

A Python-based network packet sniffer built using [Scapy](https://scapy.net/). Captures live network traffic and displays detailed packet information including IPs, protocols, ports, flags, DNS queries, HTTP requests, and payload previews.

---

## Features

- Captures live packets on any network interface
- Displays source & destination IP addresses
- Identifies protocols: TCP, UDP, ICMP, and others
- Shows TCP/UDP port numbers and TCP flag decoding
- Detects and highlights HTTP requests/responses
- Detects DNS queries
- Shows printable payload preview (first 80 bytes)
- BPF filter support for targeted capture
- Packet count limit option
- Save output to a log file
- Colour-coded terminal output
- Capture statistics summary on exit

---

## Requirements

- Python 3.7+
- Scapy library
- Root / Administrator privileges (required for raw packet capture)

### Install dependencies

```bash
pip install scapy
```

---

## Usage

```bash
# Capture all traffic on all interfaces
sudo python3 network_sniffer.py

# Capture on a specific interface
sudo python3 network_sniffer.py -i eth0

# Capture only 50 packets
sudo python3 network_sniffer.py -i eth0 -c 50

# Use a BPF filter (capture only HTTP traffic)
sudo python3 network_sniffer.py -f "tcp port 80"

# Save output to a file
sudo python3 network_sniffer.py --save capture.txt

# Combine options
sudo python3 network_sniffer.py -i wlan0 -c 100 -f "udp" --save udp_log.txt
```

---

## Sample Output

```
╔══════════════════════════════════════════════════════╗
║     CodeAlpha — Network Sniffer                      ║
║     Task 1 · Cybersecurity Internship                ║
╚══════════════════════════════════════════════════════╝

  Interface : eth0
  Count     : unlimited
  Filter    : none (all traffic)

────────────────────────────────────────────────────────
  [#1] 14:32:01.443  TCP  74 bytes
  SRC 192.168.1.5          → DST 142.250.190.78
  Port 54321 → 443  Flags: SYN  Seq: 0  Ack: 0

────────────────────────────────────────────────────────
  [#2] 14:32:01.449  UDP  73 bytes
  SRC 192.168.1.5          → DST 8.8.8.8
  Port 52341 → 53
  DNS Query: www.google.com

════════════════════════════════════════════════════════
  Capture Summary
────────────────────────────────────────────────────────
  Total packets : 2
  TCP           : 1
  UDP           : 1
════════════════════════════════════════════════════════
```

---

## How It Works

| Component | Description |
|-----------|-------------|
| `scapy.sniff()` | Captures raw packets from the network interface |
| `IP` layer | Extracts source/destination IPs and protocol number |
| `TCP` layer | Extracts ports, sequence numbers, flags |
| `UDP` layer | Extracts source/destination ports |
| `ICMP` layer | Identifies ping, redirect, and other ICMP types |
| `DNS` layer | Detects DNS queries and displays queried domain |
| `HTTP` layer | Detects HTTP methods, hosts, paths, and response codes |
| `Raw` layer | Shows printable payload bytes for inspection |

---

## BPF Filter Examples

| Filter | Captures |
|--------|----------|
| `tcp port 80` | HTTP traffic |
| `tcp port 443` | HTTPS traffic |
| `udp port 53` | DNS queries |
| `icmp` | Ping packets |
| `host 192.168.1.1` | Traffic to/from specific IP |
| `src net 192.168.1.0/24` | Traffic from local subnet |

---

## Notes

- This tool is for **educational and authorized use only**
- Always obtain proper authorization before sniffing network traffic
- Unauthorized packet capture may be illegal in your jurisdiction

---

## Project Structure

```
CodeAlpha_NetworkSniffer/
├── network_sniffer.py   # Main sniffer script
└── README.md            # Project documentation
```

---

**CodeAlpha Cybersecurity Internship** | [codealpha.tech](https://www.codealpha.tech)
