# Contributing Guidelines

## How to Contribute

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/network-packet-sniffer.git
cd network-packet-sniffer

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate  # Windows

# Install in development mode
pip install -e .
```

Code Style

· Follow PEP 8 guidelines
· Use meaningful variable names
· Add comments for complex logic
· Update documentation for new features

Testing

```bash
# Run tests
python -m pytest tests/

# Check code style
flake8 packet_sniffer.py
```

Pull Request Process

1. Update the README.md with details of changes
2. Update the requirements.txt if needed
3. Ensure all tests pass
4. Get review from at least one maintainer

```

## **GitHub Repository Description**

```

Network Packet Sniffer and Analyzer - A powerful Python tool for capturing, analyzing, and visualizing network traffic in real-time. Features include multi-protocol support, security alerts, statistical analysis, and export capabilities. Perfect for network administrators, security professionals, and students.

```

## **Tags for GitHub**
```

python, network, security, packet-sniffer, network-analysis, scapy, monitoring, cybersecurity, network-monitoring, traffic-analysis, packet-capture, network-security, forensics, network-tools, python3

```

## **How to Push to GitHub**

```bash
# Initialize git repository
git init
git add .
git commit -m "Initial commit: Network Packet Sniffer and Analyzer"

# Create repository on GitHub, then:
git remote add origin https://github.com/yourusername/network-packet-sniffer.git
git branch -M main
git push -u origin main
```
