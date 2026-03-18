
# Network Packet Sniffer Analyzer

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Scapy](https://img.shields.io/badge/scapy-2.4.5%2B-green)](https://scapy.net)

## Project Overview

During my time exploring network security and protocol analysis, I developed this packet sniffer tool that captures and analyzes network traffic in real-time. What started as a personal learning project to understand TCP/IP protocols gradually evolved into a comprehensive network monitoring solution.

## Core Capabilities

The analyzer operates at the packet level, decoding information as it traverses the network interface. Through my work on this project, I gained practical experience with:

- **Real-time Traffic Analysis** - Capturing and decoding packets as they pass through network interfaces, providing immediate visibility into network behavior
- **Multi-Protocol Support** - Deep inspection capabilities across TCP, UDP, ICMP, ARP, HTTP, HTTPS, DNS, and DHCP protocols
- **Interactive Terminal Interface** - Color-coded output that distinguishes between different protocol types and flags potential issues
- **Statistical Insights** - Comprehensive traffic analysis including protocol distribution, bandwidth utilization, and conversation patterns
- **Security Monitoring** - Automated detection of port scanning, SYN flood attempts, ARP spoofing, and anomalous traffic patterns
- **Flexible Data Export** - Capture sessions saved in JSON or CSV formats for later analysis or integration with other tools

## Technical Implementation

Building this tool required me to work through several interesting challenges in network programming. The core engine relies on Scapy for packet manipulation, while the analysis layer processes raw packet data into meaningful metrics. I implemented Berkeley Packet Filter (BPF) support to give users granular control over which packets to capture, and built a multi-threaded architecture that maintains performance even under high traffic loads.


## Practical Applications

Throughout development, I've used this tool in several practical scenarios:

In security demonstrations for fellow students, I've shown how easily unencrypted credentials can be intercepted on open networks, reinforcing the importance of using VPNs and HTTPS. The tool's ability to filter and highlight specific traffic types makes these demonstrations particularly effective.

For my own learning, I've spent countless hours watching how different applications communicate, from simple DNS queries to complex TLS handshakes. This hands-on experience has been invaluable for understanding concepts I'd only read about in textbooks.

## Getting Started

### Prerequisites
- Python 3.6 or higher
- Administrative/root access for packet capture
- libpcap (Linux) or Npcap (Windows)

### Installation

```bash
git clone https://github.com/VulnSeeker/Packet_sniffer.git
cd Packet_sniffer
pip install -r requirements.txt
```

### Basic Usage Examples

```bash
# List available network interfaces
sudo python3 packet_sniffer.py --show-interfaces

# Capture on wireless interface with protocol analysis
sudo python3 packet_sniffer.py --interface wlan0 --analyze

# Focus on web traffic with custom output
sudo python3 packet_sniffer.py --interface wlan0 --filter "tcp port 80 or tcp port 443" --output capture.json

# Generate statistics after collecting 1000 packets
sudo python3 packet_sniffer.py --interface eth0 --count 1000 --stats
```

## Sample Output

When you run the analyzer, you'll see output organized for clarity:

```
[2024-01-15 14:30:25.123456] Packet #1247
├─ Protocol: TCP (Port 443 → HTTPS)
├─ Source: 192.168.1.100:51234
├─ Destination: 142.250.185.78:443
├─ Flags: [SYN, ACK] Connection Established
├─ Size: 543 bytes
└─ Payload: TLSv1.3 Client Hello

Traffic Summary (Last 60 seconds):
├─ 1,247 packets | 1.2 MB transferred
├─ Top Talker: 192.168.1.100 (45% of traffic)
└─ Security: No anomalies detected
```

## Development Journey

This project represents countless late nights of debugging packet capture code, understanding why certain packets wouldn't decode properly, and gradually building up the analysis capabilities. I remember the satisfaction when I finally got the ARP spoofing detection working correctly - it meant understanding not just how ARP works, but how malicious actors might abuse it and what patterns give them away.

Working with raw network data taught me patience and attention to detail. One misplaced bit in a packet header could break the entire analysis chain. Through this process, I developed a deeper appreciation for the elegant design of network protocols and the complexity of the systems that keep our internet running.

## What I Learned

Beyond the technical skills in Python, Scapy, and network programming, this project taught me about:

- **Problem decomposition** - Breaking down complex packet structures into manageable analysis components
- **Performance optimization** - Processing high-volume network streams without dropping packets
- **Security mindset** - Understanding how network behavior differs between normal operation and attack scenarios
- **Documentation value** - The importance of clear code comments and user guides for tools that others might use

## Looking Forward

I continue to maintain and improve this tool as I learn new techniques. Recent additions include better visualization options and more sophisticated anomaly detection algorithms. The project has become a portfolio piece that demonstrates my ability to build practical security tools while understanding the underlying network fundamentals.

---

*This tool is released under the MIT License and is intended for educational purposes and authorized network analysis only. Please ensure you have permission to monitor any network where you use this software.*
