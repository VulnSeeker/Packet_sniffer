# Network Packet Sniffer and Analyzer 🔍

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Scapy](https://img.shields.io/badge/scapy-2.4.5%2B-green)](https://scapy.net)

A powerful, real-time network packet sniffer and analyzer written in Python. Capture, analyze, and visualize network traffic with detailed protocol information and security alerts.

![Packet Sniffer Demo](docs/demo.gif)

## ✨ Features

- **Real-time Packet Capture**: Live monitoring of network traffic
- **Multi-Protocol Support**: TCP, UDP, ICMP, ARP, HTTP, HTTPS, DNS, DHCP
- **Color-coded Output**: Easy-to-read terminal display
- **Statistical Analysis**: Protocol distribution, top talkers, active connections
- **Security Alerts**: SYN flood detection, port scan detection, unusual traffic patterns
- **Export Capabilities**: Save captures to JSON and CSV formats
- **BPF Filter Support**: Use Berkeley Packet Filter expressions
- **Cross-Platform**: Works on Linux, macOS, and Windows

## 🚀 Quick Start

### Prerequisites
- Python 3.6 or higher
- Administrative/root privileges
- libpcap/Npcap installed

### Installation

```bash
# Clone the repository
git clone https://github.com/VulnSeeker/network-packet-sniffer.git
cd network-packet-sniffer

# Install dependencies
pip install -r requirements.txt

# On Linux, install libpcap
sudo apt-get install libpcap-dev  # Debian/Ubuntu
# or
sudo yum install libpcap-devel    # RHEL/CentOS
```

Basic Usage

```bash
# List available network interfaces
sudo python3 packet_sniffer.py --list-interfaces

# Capture on specific interface
sudo python3 packet_sniffer.py -i eth0

# Capture HTTP traffic only
sudo python3 packet_sniffer.py -i eth0 -f "tcp port 80"

# Capture 100 packets and save to file
sudo python3 packet_sniffer.py -i eth0 -c 100 -o capture.json
```

📊 Example Output

```
[1] 2024-01-15 14:30:25.123456
  Protocol: TCP
  Source: 192.168.1.100:51234
  Destination: 142.250.185.78:443
  TCP Flags: SYN ACK
  Size: 543 bytes

[2] 2024-01-15 14:30:25.234567
  Protocol: DNS
  Source: 192.168.1.100:54321
  Destination: 8.8.8.8:53
  Info: DNS Query: google.com
  Size: 78 bytes
```

🛡️ Security Features

The analyzer automatically detects:

· Port scanning attempts
· SYN flood attacks
· Unusually high traffic volumes
· ARP spoofing
· Suspicious connection patterns

📈 Statistics Report

After capture, the tool generates a comprehensive report:

· Capture duration and total packets
· Protocol distribution
· Top talkers by traffic volume
· Active connections
· Security alerts

🔧 Advanced Usage

```bash
# Complex BPF filter
sudo python3 packet_sniffer.py -i eth0 -f "host 192.168.1.100 and tcp port 443"

# Monitor specific subnet
sudo python3 packet_sniffer.py -i eth0 -f "net 192.168.1.0/24"

# Exclude local traffic
sudo python3 packet_sniffer.py -i eth0 -f "not arp and not icmp"

# Save to custom file
sudo python3 packet_sniffer.py -i eth0 -o my_capture.json
```

📚 Documentation

· Installation Guide
· Usage Examples
· API Reference
· Filter Expressions

🤝 Contributing

Contributions are welcome! Please read our Contributing Guidelines before submitting a pull request.

⚠️ Legal Disclaimer

This tool is for educational purposes and authorized testing only. Users are responsible for complying with all applicable laws and regulations. Unauthorized packet sniffing may be illegal in your jurisdiction.

Only use this tool on:

· Networks you own
· Networks you have explicit permission to test
· Your own devices

📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

🙏 Acknowledgments

· Scapy - Packet manipulation library
· Pandas - Data analysis
· BPF - Packet filtering

📬 Contact

· Create an Issue for bug reports
· Start a Discussion for questions

---

⭐ Star this repository if you find it useful!
