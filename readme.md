network packet sniffer analyzer

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Scapy](https://img.shields.io/badge/scapy-2.4.5%2B-green)](https://scapy.net)

This tool runs on Python, pulling data directly from networks while it travels. Right before your eyes, traffic flows appear in simple graphics that reveal protocol actions. When a threat shows up in the stream, warnings appear instantly. Information becomes visible quickly once collected, no waiting, no added stages. What happens next unfolds clearly, step by step.


✨ Features

Monitor live network traffic
Handles various communication methods such as tcp alongside udp, icmp paired with arp, then http followed by https, plus dns combined with dhcp
Color Coded Terminal Output
Protocol Distribution Top Talkers Active Connections
Fast bursts of connections raise flags. When port checks line up, patterns change. Odd timing in data flow catches attention.
Save captures as JSON or CSV
BPF Filter Support Using Berkeley Packet Expressions
Cross Platform Support Linux macOS Windows

🚀 Quick Start

Prerequisites
Last time someone tried it, things went sideways without the right setup. Whatever you do, make sure your Python isn’t stuck in the past. Newer than 3.6? Good. That one plays along just fine. Trouble usually starts when nobody checks until it’s too late
- Administrative/root privileges
- libpcap/Npcap installed

Installation

```bash
Clone the repository
git clone https://github.com/VulnSeeker/Packet_sniffer.git
cd Packet_sniffer

Install dependencies
Begin with pip install, include -r next. After that comes the filename: requirements.txt

Install libpcap on Linux
sudo apt-get install libpcap-dev Debian/Ubuntu
or
sudo yum install libpcap-devel RHEL/CentOS
```

Basic Usage

```bash
List available network interfaces
Run the script packet_sniffer.py using administrator rights to show available network ports

Capture on specific interface
Start by launching the script through python three, making sure it has full admin access. Aim it at the wlan zero connection point during execution. Running it needs elevated permissions for proper function. The process begins only when privileges are confirmed active. Targeting the correct wireless interface ensures accurate results each time

Capture Only HTTP Traffic
Start the script with full system access through python three. Pick your wireless connection by entering wlan zero. Focus on traffic moving across transmission control protocol port eighty.

A handful of boxes comes first. After that, tuck them away inside a folder
Start by launching the script through Python version three with elevated privileges. Pick the wireless adapter labeled wlan0 for data collection. Gather a total of one hundred frames during the session. Place the recorded information into a file called capture.json.
```

📊 Example Output

```
[1] 2024-01-15 14:30:25.123456
Protocol: TCP
Source: 192.168.1.100:51234
Destination: 142.250.185.78:443
TCP Flags Syn Ack
Size: 543 bytes

[2] 2024-01-15 14:30:25.234567
Protocol: DNS
Source: 192.168.1.100:54321
Destination: 8.8.8.8:53
DNS Query for google com
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

Then came the grab - just like that, everything spilled out. One fact after another hit the surface, clear and unhidden. Each detail arrived in line, nothing skipped. The whole picture formed fast, right there on display

Last thing first - how long it ran, plus how many bits came through. Timing matters just as much as count
· Protocol distribution
· Top talkers by traffic volume
· Active connections
· Security alerts

🔧 Advanced Usage

```bash
Complex BPF filter
Using Python 3, start the script with administrator access on the wlan0 interface. Through port numbers used for encrypted web traffic, monitor data heading to 192.168.1.100. Set up filters that catch only packets aimed at that address. With elevated permissions active, launch execution now. Focus stays on HTTPS-related flows during operation. Configuration applies strictly to the specified network point.

Monitor specific subnet
Start things off by launching the script through Python 3, making sure it has full system access. Pick wlan0 when asked where to grab data from. Focus only on packets coming from addresses between 192.168.1.0 and 192.168.1.255

Exclude local traffic
Start by launching the script through python three while holding administrator access. Pick wlan zero as the wireless port to work with. Remove every request tied to addresses without exception. Pass over any data related to ping testing as well. What stays behind - just that gets recorded.

Keep it inside a folder you created yourself
Start things off by launching the script through python three, making sure it has full system access. Pick your wireless connection point - wlan zero is what you want here. The results will land in a file named my capture dot j s o n when done.
```


🤝 Contributing

Something on your mind? Check the Contributing Guidelines before you begin. Once set, submit your pull request whenever it feels right.

⚠️ Legal Disclaimer

Out of nowhere, doing something that seems fine might land you in trouble. Even if a tool functions perfectly, using it without limits isn’t always safe. In certain areas, pulling unseen information acts like trespassing in the eyes of law enforcement. A classroom may permit such actions, but nearby regulations often carry their own consequences. Without looking up what's allowed, stepping into surveillance territory risks unexpected costs. Something appearing innocent online might be seen as forced entry once courts get involved.

This tool works only for:

Focused on your connections before anything else
Where permission comes through a signed document, that's when entry happens. A paper trail decides who gets in. Without something on file, doors stay shut. Approval shows up only if it’s spelled out ahead of time. Access appears solely under documented terms
· Your own devices

📄 License

A license is in effect for this project - look inside the LICENSE file to see exactly which one. Following MIT rules, these terms appear plainly wherever they’re posted.

🙏 Acknowledgments

Scapy packet manipulation library
Pandas for data analysis

Last thing - if this one sticks with you, toss it a star anytime. Support shows up in small ways.
