#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════╗
║       CodeAlpha — Cybersecurity Internship           ║
║       Task 1: Basic Network Sniffer                  ║
║       Author : <Your Name>                           ║
║       Language: Python 3  |  Library: scapy          ║
╚══════════════════════════════════════════════════════╝

Description:
    Captures live network packets and displays:
      - Source & Destination IP addresses
      - Protocol (TCP / UDP / ICMP / Other)
      - Source & Destination ports (TCP/UDP)
      - Payload preview (first 80 bytes, printable chars)
      - Packet size & timestamp

Usage:
    sudo python3 network_sniffer.py                   # sniff all interfaces
    sudo python3 network_sniffer.py -i eth0           # specific interface
    sudo python3 network_sniffer.py -i eth0 -c 50     # capture 50 packets
    sudo python3 network_sniffer.py -f "tcp port 80"  # BPF filter
    sudo python3 network_sniffer.py --save log.txt    # save output to file

Requirements:
    pip install scapy
    Must be run with root / administrator privileges.
"""

import argparse
import datetime
import sys
import os
from collections import defaultdict

# ── Dependency check ────────────────────────────────────────────────────────
try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw, Ether, conf
    from scapy.layers.dns import DNS, DNSQR
    from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
except ImportError:
    print("[ERROR] scapy is not installed. Run: pip install scapy")
    sys.exit(1)

# ── Colour helpers (works on Linux/Mac; degrades gracefully on Windows) ──────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
GREY   = "\033[90m"

def c(text, colour):
    """Wrap text in ANSI colour code."""
    return f"{colour}{text}{RESET}"

# ── Protocol map ─────────────────────────────────────────────────────────────
PROTO_MAP = {1: "ICMP", 6: "TCP", 17: "UDP", 41: "IPv6", 89: "OSPF"}

# ── Statistics tracker ───────────────────────────────────────────────────────
stats = defaultdict(int)
packet_counter = 0


# ═════════════════════════════════════════════════════════════════════════════
#  Core packet handler
# ═════════════════════════════════════════════════════════════════════════════

def packet_handler(packet, log_file=None):
    """Parse and display a single captured packet."""
    global packet_counter
    packet_counter += 1

    # ── Only process packets with an IP layer ────────────────────────────────
    if not packet.haslayer(IP):
        return

    ip_layer   = packet[IP]
    src_ip     = ip_layer.src
    dst_ip     = ip_layer.dst
    proto_num  = ip_layer.proto
    proto_name = PROTO_MAP.get(proto_num, f"OTHER({proto_num})")
    pkt_size   = len(packet)
    timestamp  = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]

    stats[proto_name] += 1
    stats["total"]    += 1

    # ── Build output lines ───────────────────────────────────────────────────
    lines = []
    lines.append(
        f"\n{c('─' * 64, GREY)}\n"
        f"  {c(f'[#{packet_counter}]', BOLD)} {c(timestamp, GREY)}  "
        f"{c(proto_name, proto_colour(proto_name))}  "
        f"{c(f'{pkt_size} bytes', GREY)}"
    )
    lines.append(f"  {c('SRC', CYAN)} {src_ip:<20} → {c('DST', YELLOW)} {dst_ip}")

    # ── TCP details ──────────────────────────────────────────────────────────
    if packet.haslayer(TCP):
        tcp = packet[TCP]
        flags = decode_tcp_flags(tcp.flags)
        lines.append(
            f"  {c('Port', GREY)} {tcp.sport} → {tcp.dport}  "
            f"Flags: {c(flags, RED)}  Seq: {tcp.seq}  Ack: {tcp.ack}"
        )
        # HTTP detection
        if packet.haslayer(HTTPRequest):
            req = packet[HTTPRequest]
            method = req.Method.decode(errors='replace') if req.Method else "?"
            host   = req.Host.decode(errors='replace')   if req.Host   else "?"
            path   = req.Path.decode(errors='replace')   if req.Path   else "/"
            lines.append(f"  {c('HTTP', GREEN)} {method} {host}{path}")
        elif packet.haslayer(HTTPResponse):
            resp = packet[HTTPResponse]
            code = resp.Status_Code.decode(errors='replace') if resp.Status_Code else "?"
            lines.append(f"  {c('HTTP', GREEN)} Response {code}")

    # ── UDP details ──────────────────────────────────────────────────────────
    elif packet.haslayer(UDP):
        udp = packet[UDP]
        lines.append(f"  {c('Port', GREY)} {udp.sport} → {udp.dport}")
        # DNS detection
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            qname = packet[DNSQR].qname.decode(errors='replace').rstrip('.')
            lines.append(f"  {c('DNS', BLUE)} Query: {qname}")

    # ── ICMP details ─────────────────────────────────────────────────────────
    elif packet.haslayer(ICMP):
        icmp = packet[ICMP]
        icmp_types = {0: "Echo Reply", 8: "Echo Request", 3: "Dest Unreachable",
                      11: "Time Exceeded", 5: "Redirect"}
        icmp_type = icmp_types.get(icmp.type, f"Type {icmp.type}")
        lines.append(f"  {c('ICMP', YELLOW)} {icmp_type} (code {icmp.code})")

    # ── Payload preview ──────────────────────────────────────────────────────
    if packet.haslayer(Raw):
        raw_bytes = bytes(packet[Raw].load)
        printable = ''.join(
            chr(b) if 32 <= b < 127 else '.' for b in raw_bytes[:80]
        )
        if printable.strip('.'):
            lines.append(f"  {c('Payload', GREY)} {printable}")

    output = "\n".join(lines)
    print(output)

    if log_file:
        # Strip ANSI codes when writing to file
        import re
        clean = re.sub(r'\033\[[0-9;]*m', '', output)
        log_file.write(clean + "\n")
        log_file.flush()


# ── Helpers ──────────────────────────────────────────────────────────────────

def proto_colour(proto):
    return {
        "TCP":  GREEN,
        "UDP":  BLUE,
        "ICMP": YELLOW,
    }.get(proto, GREY)


def decode_tcp_flags(flags):
    """Return a human-readable TCP flags string."""
    flag_map = [
        ("F", "FIN"), ("S", "SYN"), ("R", "RST"),
        ("P", "PSH"), ("A", "ACK"), ("U", "URG"),
    ]
    active = [name for bit, name in flag_map if bit in str(flags)]
    return "|".join(active) if active else str(flags)


def print_stats():
    """Print capture statistics summary."""
    print(f"\n{c('═' * 64, GREY)}")
    print(f"  {c('Capture Summary', BOLD)}")
    print(f"{c('─' * 64, GREY)}")
    print(f"  Total packets : {c(str(stats['total']), CYAN)}")
    for proto in ("TCP", "UDP", "ICMP"):
        if stats[proto]:
            print(f"  {proto:<14}: {stats[proto]}")
    other = stats['total'] - stats['TCP'] - stats['UDP'] - stats['ICMP']
    if other > 0:
        print(f"  {'Other':<14}: {other}")
    print(f"{c('═' * 64, GREY)}\n")


def print_banner(interface, count, bpf_filter):
    """Print startup banner."""
    print(f"""
{c('╔══════════════════════════════════════════════════════╗', CYAN)}
{c('║', CYAN)}     {c('CodeAlpha — Network Sniffer', BOLD)}                    {c('║', CYAN)}
{c('║', CYAN)}     Task 1 · Cybersecurity Internship               {c('║', CYAN)}
{c('╚══════════════════════════════════════════════════════╝', CYAN)}

  {c('Interface', GREY)} : {c(interface or 'all', GREEN)}
  {c('Count    ', GREY)} : {c(str(count) if count else 'unlimited', GREEN)}
  {c('Filter   ', GREY)} : {c(bpf_filter or 'none (all traffic)', GREEN)}
  {c('Started  ', GREY)} : {c(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), GREEN)}

  {c('Press Ctrl+C to stop', YELLOW)}
""")


# ═════════════════════════════════════════════════════════════════════════════
#  CLI entry point
# ═════════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="CodeAlpha Task 1 — Python Network Sniffer using Scapy",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python3 network_sniffer.py
  sudo python3 network_sniffer.py -i eth0 -c 100
  sudo python3 network_sniffer.py -f "tcp port 443"
  sudo python3 network_sniffer.py -i wlan0 --save capture.txt
        """
    )
    parser.add_argument("-i", "--interface", default=None,
                        help="Network interface to sniff (default: all)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Number of packets to capture (default: 0 = unlimited)")
    parser.add_argument("-f", "--filter", dest="bpf_filter", default=None,
                        help="BPF filter string, e.g. 'tcp port 80'")
    parser.add_argument("--save", metavar="FILE", default=None,
                        help="Save output to a text file")
    args = parser.parse_args()

    # Privilege check
    if os.name != 'nt' and os.geteuid() != 0:
        print(c("[ERROR] Please run as root: sudo python3 network_sniffer.py", RED))
        sys.exit(1)

    print_banner(args.interface, args.count, args.bpf_filter)

    log_file = None
    if args.save:
        log_file = open(args.save, "w", encoding="utf-8")
        print(c(f"  Logging to: {args.save}\n", GREY))

    try:
        sniff(
            iface=args.interface,
            count=args.count,
            filter=args.bpf_filter,
            prn=lambda pkt: packet_handler(pkt, log_file),
            store=False,          # don't keep packets in memory
        )
    except KeyboardInterrupt:
        print(c("\n\n  [Stopped by user]", YELLOW))
    except PermissionError:
        print(c("\n[ERROR] Permission denied — run with sudo.", RED))
    finally:
        print_stats()
        if log_file:
            log_file.close()
            print(c(f"  Log saved to: {args.save}", GREEN))


if __name__ == "__main__":
    main()
