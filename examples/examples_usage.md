
# Basic Usage Examples

## Example 1: Monitor Home Network
```bash
# Find your interface
sudo python3 packet_sniffer.py --list-interfaces

# Start monitoring
sudo python3 packet_sniffer.py -i wlan0
```

Example 2: Capture Web Traffic

```bash
# HTTP only
sudo python3 packet_sniffer.py -i eth0 -f "tcp port 80"

# HTTPS only
sudo python3 packet_sniffer.py -i eth0 -f "tcp port 443"
```

Example 3: DNS Analysis

```bash
# Capture DNS queries
sudo python3 packet_sniffer.py -i eth0 -f "udp port 53" -o dns_traffic.json
```

Example 4: Targeted Capture

```bash
# Monitor specific device
sudo python3 packet_sniffer.py -i wlan0 -f "host 192.168.1.105"
```

Example 5: Limited Capture

```bash
# Capture exactly 500 packets
sudo python3 packet_sniffer.py -i eth0 -c 500 -o sample.json
```
