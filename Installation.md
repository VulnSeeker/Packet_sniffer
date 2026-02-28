# Installation Guide

## 🐧 Linux (Ubuntu/Debian)

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install Python and pip
sudo apt install python3 python3-pip -y

# Install libpcap
sudo apt install libpcap-dev -y

# Clone repository
git clone https://github.com/VulnSeeker/Packet_sniffer.git
cd Packet_sniffer

# Install Python packages
pip3 install -r requirements.txt
```

🐧 Linux (RHEL/CentOS/Fedora)

```bash
# Install dependencies
sudo yum install python3 python3-pip libpcap-devel
# or
sudo dnf install python3 python3-pip libpcap-devel

# Clone and install
git clone https://github.com/VulnSeeker/Packet_sniffer.git
cd Packet_sniffer
pip3 install -r requirements.txt
```

🍎 macOS

```bash
# Install Homebrew if not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install dependencies
brew install python3 libpcap

# Clone repository
git clone https://github.com/VulnSeeker/Packet_sniffer.git
cd Packet_sniffer

# Install Python packages
pip3 install -r requirements.txt
```

🪟 Windows

1. Install Python 3.6+ from python.org
   · ✅ IMPORTANT: Check "Add Python to PATH" during installation
2. Install Npcap from npcap.com
   · ✅ IMPORTANT: Check "WinPcap API-compatible Mode" during installation
3. Open Command Prompt as Administrator and run:

```cmd
git clone https://github.com/VulnSeeker/Packet_sniffer.git
cd Packet_sniffer
pip install -r requirements.txt
```

1. If Git is not installed, download ZIP from GitHub instead:
   · Extract folder
   · Open Command Prompt in that folder
   · Run: pip install -r requirements.txt

✅ Verify Installation

After installation, test with:

```bash
# Linux/macOS
python3 packet_sniffer.py --help

# Windows
python packet_sniffer.py --help
```
