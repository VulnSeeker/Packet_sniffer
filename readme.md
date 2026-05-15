# Packet Sniffer

_A lightweight CLI tool to capture, analyze, and display network traffic in real-time._

---

## 📌 Problem Statement

In an increasingly connected digital world, understanding network traffic is crucial for ensuring security, diagnosing issues, and optimizing performance. Conventional packet sniffers are often overly complex, resource-intensive, or require steep learning curves, limiting their usability for students, professionals, and enthusiasts seeking quick yet comprehensive network insight.

---

## 💡 Solution

**Packet Sniffer** addresses these challenges by providing:
- **Simplicity**: An intuitive command-line interface without sacrificing analysis depth.
- **Performance**: Lightweight implementation in Python for rapid deployment and minimal overhead.
- **Adaptability**: Cross-platform compatibility with customizable filters.

This tool empowers users to capture, monitor, and analyze network packets in real-time, turning complex raw traffic into actionable information.

---

## ✨ Features

- **Real-Time Packet Capture**  
  Capture live network packets from any selected interface with instant output.

- **Comprehensive Protocol Analysis**  
  Decode and display key protocols (TCP, UDP, ICMP, ARP, etc.) with detailed packet metadata.

- **Customizable Filters**  
  Apply filters (e.g., by protocol, port, IP) to focus on traffic relevant to your analysis.

- **Traffic Summarization**  
  Summarize captured traffic, such as top talkers, protocol distribution, or packet size statistics.

- **User-Friendly CLI**  
  Intuitive and well-documented command-line options for seamless experience.

- **Cross-Platform Support**  
  Compatible with major operating systems: Linux, Windows, macOS.

- **Export Capabilities**  
  Export raw data or processed summaries for further investigation or reporting.

---

## 🚀 How It Works

1. **Interface Selection:**  
   On launch, the tool lists available network interfaces, allowing users to select the desired one.

2. **Packet Capture:**  
   Utilizes efficient socket programming and third-party libraries (e.g., scapy) to sniff packets.

3. **Analysis:**  
   Parses packet headers and payloads, extracting source/destination addresses, ports, flags, and more.

4. **Display:**  
   Formats and outputs relevant information in real-time, with color-coded or tabulated views for clarity.

5. **Export/Save:**  
   Optional saving of packets or statistics to files (CSV, JSON, etc.) for offline analysis.

---

## 🛠️ Technologies Used

- **Language:** Python (100%)  
- **Key Libraries:**  
  - `scapy`: Powerful interactive packet manipulation tool and library
  - Standard Python libraries: `socket`, `argparse`, `struct`, `datetime`

---

## 🏆 Why This Project Stands Out

- Designed from the ground up for **clarity**, **usability**, and **educational value**.
- Balances **depth** (detailed analysis) with **accessibility** (lightweight, easy to use).
- Fosters **network literacy** for aspiring cybersecurity professionals, system admins, and learners.

---

## 📚 Usage

```bash
python packet_sniffer.py --interface <interface> [--filter <expression>] [--output <file>]
```

For a full list of options:
```bash
python packet_sniffer.py --help
```

---

## 📈 Example Output

```
Time         Source           Destination      Protocol Length Info
12:34:01.789 192.168.0.12     142.250.183.206 TCP      74     SYN to port 443
...
```

---

## 🤝 Contributing

Contributions, feature requests, and bug reports are welcome! Please open an issue or submit a pull request.

---

## ⚖️ License

MIT License (see `LICENSE` file for details).

---

## 🙋‍♂️ Author

Developed and maintained by [VulnSeeker](https://github.com/VulnSeeker)

---

## ⭐️ If you find this project useful, please consider starring the repository!
