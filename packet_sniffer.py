#!/usr/bin/env python3
"""
Network Packet Sniffer and Analyzer
Author: Network Security Tool
Description: Captures and analyzes network packets with protocol details
Version: 2.0.0
"""

import argparse
import signal
import sys
import time
import json
import os
import logging
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from typing import Dict, List, Optional, Any, Tuple
import threading
import queue
from dataclasses import dataclass, field, asdict
from enum import Enum

# Third-party imports with error handling
try:
    from scapy.all import *
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.layers.l2 import Ether, ARP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.dhcp import DHCP
    from scapy.error import Scapy_Exception
    SCAPY_AVAILABLE = True
except ImportError as e:
    print(f"[!] Scapy import error: {e}")
    print("[!] Please install scapy: pip install scapy")
    SCAPY_AVAILABLE = False
    sys.exit(1)

try:
    import pandas as pd
    PANDAS_AVAILABLE = True
except ImportError:
    PANDAS_AVAILABLE = False
    print("[!] Pandas not installed. CSV export disabled.")
    print("[!] Install with: pip install pandas")

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False
    print("[!] Colorama not installed. Using basic colors.")
    print("[!] Install with: pip install colorama for better colors")

# Configuration
CONFIG = {
    'max_packets_memory': 10000,  # Max packets to keep in memory
    'alert_threshold': {
        'packets_per_second': 1000,
        'syn_flood': 100,
        'port_scan_ports': 20,
        'high_traffic_packets': 1000
    },
    'buffer_size': 1024 * 1024,  # 1MB buffer
    'timeout': 60,  # Capture timeout in seconds
    'stats_interval': 10,  # Statistics display interval
    'geoip_enabled': False,  # Disable by default to avoid dependencies
    'dns_cache_size': 1000
}

class PacketProtocol(Enum):
    """Enhanced protocol enumeration"""
    TCP = "TCP"
    UDP = "UDP"
    ICMP = "ICMP"
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    DNS = "DNS"
    DHCP = "DHCP"
    ARP = "ARP"
    IPv6 = "IPv6"
    IGMP = "IGMP"
    GRE = "GRE"
    ESP = "ESP"
    AH = "AH"
    OSPF = "OSPF"
    SCTP = "SCTP"
    UNKNOWN = "UNKNOWN"

@dataclass
class PacketAnalysis:
    """Enhanced packet analysis dataclass"""
    timestamp: str
    protocol: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    size: int = 0
    flags: Optional[int] = None
    flags_str: Optional[str] = None
    info: str = ''
    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None
    ttl: Optional[int] = None
    seq: Optional[int] = None
    ack: Optional[int] = None
    window: Optional[int] = None
    options: Optional[Dict] = None
    payload_size: int = 0
    payload_hash: Optional[str] = None
    geoip_src: Optional[Dict] = None
    geoip_dst: Optional[Dict] = None
    dns_query: Optional[str] = None
    dns_response: Optional[List[str]] = None
    http_method: Optional[str] = None
    http_host: Optional[str] = None
    http_path: Optional[str] = None
    http_status: Optional[int] = None
    http_user_agent: Optional[str] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    vlan_id: Optional[int] = None
    mpls_labels: Optional[List] = None

class EnhancedColor:
    """Enhanced color handling with fallback"""
    if COLORAMA_AVAILABLE:
        RED = Fore.RED
        GREEN = Fore.GREEN
        YELLOW = Fore.YELLOW
        BLUE = Fore.BLUE
        MAGENTA = Fore.MAGENTA
        CYAN = Fore.CYAN
        WHITE = Fore.WHITE
        RESET = Style.RESET_ALL
        BOLD = Style.BRIGHT
    else:
        RED = '\033[91m'
        GREEN = '\033[92m'
        YELLOW = '\033[93m'
        BLUE = '\033[94m'
        MAGENTA = '\033[95m'
        CYAN = '\033[96m'
        WHITE = '\033[97m'
        RESET = '\033[0m'
        BOLD = '\033[1m'

class PacketProcessor:
    """Handles packet processing in separate thread"""
    
    def __init__(self, analyzer, max_queue_size=1000):
        self.analyzer = analyzer
        self.packet_queue = queue.Queue(maxsize=max_queue_size)
        self.running = True
        self.processor_thread = threading.Thread(target=self._process_packets)
        self.processor_thread.daemon = True
        self.processor_thread.start()
        
    def _process_packets(self):
        """Process packets from queue"""
        while self.running:
            try:
                packet = self.packet_queue.get(timeout=1)
                self.analyzer._analyze_packet_sync(packet)
            except queue.Empty:
                continue
            except Exception as e:
                print(f"{EnhancedColor.RED}[!] Error processing packet: {e}{EnhancedColor.RESET}")
                
    def add_packet(self, packet):
        """Add packet to processing queue"""
        try:
            self.packet_queue.put_nowait(packet)
        except queue.Full:
            pass  # Drop packet if queue is full
            
    def stop(self):
        """Stop processor thread"""
        self.running = False
        self.processor_thread.join(timeout=5)

class ThreatDetector:
    """Enhanced threat detection"""
    
    def __init__(self):
        self.scan_tracker = defaultdict(lambda: {
            'ports': set(),
            'syn_count': 0,
            'timestamp': datetime.now(),
            'alerts': []
        })
        self.ddos_tracker = defaultdict(lambda: {
            'packets': [],
            'bytes': [],
            'last_alert': None
        })
        self.arp_spoof_tracker = defaultdict(lambda: {
            'mac_addresses': set(),
            'last_seen': None
        })
        self.alert_history = []
        
    def detect_port_scan(self, packet, analysis):
        """Enhanced port scan detection"""
        if analysis.protocol in ['TCP', 'UDP'] and analysis.src_ip:
            tracker = self.scan_tracker[analysis.src_ip]
            
            if analysis.protocol == 'TCP' and 'SYN' in (analysis.flags_str or ''):
                tracker['syn_count'] += 1
                
            if analysis.dst_port:
                tracker['ports'].add(analysis.dst_port)
                
            # Check for port scan patterns
            if len(tracker['ports']) > CONFIG['alert_threshold']['port_scan_ports']:
                if time.time() - tracker['timestamp'].timestamp() < 10:  # Within 10 seconds
                    alert = {
                        'type': 'PORT_SCAN',
                        'src_ip': analysis.src_ip,
                        'ports_scanned': len(tracker['ports']),
                        'timestamp': datetime.now().isoformat(),
                        'severity': 'HIGH'
                    }
                    self.alert_history.append(alert)
                    tracker['alerts'].append(alert)
                    return alert
                    
        return None
        
    def detect_ddos(self, packet, analysis):
        """Enhanced DDoS detection"""
        if analysis.dst_ip:
            tracker = self.ddos_tracker[analysis.dst_ip]
            now = time.time()
            
            # Keep last 60 seconds of data
            tracker['packets'] = [t for t in tracker['packets'] if now - t < 60]
            tracker['bytes'] = [b for b in tracker['bytes'] if now - b[0] < 60]
            
            tracker['packets'].append(now)
            tracker['bytes'].append((now, analysis.size))
            
            # Calculate packets per second
            if len(tracker['packets']) > 1:
                time_span = tracker['packets'][-1] - tracker['packets'][0]
                if time_span > 0:
                    pps = len(tracker['packets']) / time_span
                    
                    if pps > CONFIG['alert_threshold']['packets_per_second']:
                        if not tracker['last_alert'] or now - tracker['last_alert'] > 30:
                            alert = {
                                'type': 'DDoS',
                                'dst_ip': analysis.dst_ip,
                                'packets_per_second': pps,
                                'timestamp': datetime.now().isoformat(),
                                'severity': 'CRITICAL'
                            }
                            self.alert_history.append(alert)
                            tracker['last_alert'] = now
                            return alert
                            
        return None
        
    def detect_arp_spoof(self, packet, analysis):
        """ARP spoofing detection"""
        if analysis.protocol == 'ARP' and analysis.src_ip and analysis.src_mac:
            tracker = self.arp_spoof_tracker[analysis.src_ip]
            
            if tracker['mac_addresses'] and analysis.src_mac not in tracker['mac_addresses']:
                alert = {
                    'type': 'ARP_SPOOF',
                    'ip': analysis.src_ip,
                    'mac_addresses': list(tracker['mac_addresses']) + [analysis.src_mac],
                    'timestamp': datetime.now().isoformat(),
                    'severity': 'CRITICAL'
                }
                self.alert_history.append(alert)
                return alert
                
            tracker['mac_addresses'].add(analysis.src_mac)
            tracker['last_seen'] = datetime.now()
            
        return None

class PacketAnalyzer:
    """Enhanced main packet analyzer class"""
    
    def __init__(self, interface=None, filter_expr=None, output_file=None, 
                 verbose=False, stats_interval=10, max_packets=0):
        self.interface = interface
        self.filter_expr = filter_expr
        self.output_file = output_file
        self.verbose = verbose
        self.stats_interval = stats_interval
        self.max_packets = max_packets
        
        # State management
        self.running = True
        self.paused = False
        self.start_time = datetime.now()
        self.last_stats_time = datetime.now()
        
        # Statistics
        self.packet_count = 0
        self.captured_packets = []
        self.protocol_stats = defaultdict(int)
        self.ip_stats = defaultdict(lambda: defaultdict(int))
        self.connection_stats = defaultdict(lambda: defaultdict(int))
        self.port_stats = defaultdict(lambda: defaultdict(int))
        self.protocol_trends = defaultdict(list)
        
        # Enhanced features
        self.packet_processor = PacketProcessor(self)
        self.threat_detector = ThreatDetector()
        self.dns_cache = {}
        self.geoip_cache = {}
        
        # Performance monitoring
        self.processing_times = []
        self.drop_count = 0
        
        # Setup logging
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        log_format = '%(asctime)s - %(levelname)s - %(message)s'
        logging.basicConfig(
            level=logging.INFO if self.verbose else logging.WARNING,
            format=log_format,
            handlers=[
                logging.FileHandler('packet_sniffer.log'),
                logging.StreamHandler() if self.verbose else logging.NullHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
    def signal_handler(self, sig, frame):
        """Enhanced signal handler"""
        print(f"\n{EnhancedColor.YELLOW}[!] Stopping packet capture...{EnhancedColor.RESET}")
        self.running = False
        self.packet_processor.stop()
        self.generate_report()
        sys.exit(0)
        
    def get_protocol_name(self, packet) -> str:
        """Enhanced protocol name detection"""
        # IPv6
        if packet.haslayer(IPv6):
            return "IPv6"
            
        # TCP with port analysis
        if packet.haslayer(TCP):
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            
            # Common service detection
            common_ports = {
                80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
                25: "SMTP", 53: "DNS", 110: "POP3", 143: "IMAP",
                993: "IMAPS", 995: "POP3S", 3389: "RDP", 5900: "VNC",
                8080: "HTTP-ALT", 8443: "HTTPS-ALT"
            }
            
            if sport in common_ports:
                return common_ports[sport]
            if dport in common_ports:
                return common_ports[dport]
                
            return "TCP"
            
        # UDP
        elif packet.haslayer(UDP):
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            
            if sport == 53 or dport == 53:
                return "DNS"
            elif sport == 67 or dport == 67 or sport == 68 or dport == 68:
                return "DHCP"
            elif sport == 123 or dport == 123:
                return "NTP"
            elif sport == 161 or dport == 161:
                return "SNMP"
            elif sport == 514 or dport == 514:
                return "SYSLOG"
            elif sport == 500 or dport == 500:
                return "IKE"
            else:
                return "UDP"
                
        # ICMP
        elif packet.haslayer(ICMP):
            return "ICMP"
            
        # ARP
        elif packet.haslayer(ARP):
            return "ARP"
            
        # Other IP protocols
        elif packet.haslayer(IP):
            proto = packet[IP].proto
            protocol_map = {
                1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP",
                47: "GRE", 50: "ESP", 51: "AH", 89: "OSPF",
                132: "SCTP"
            }
            return protocol_map.get(proto, f"IP-{proto}")
            
        # Ethernet only
        elif packet.haslayer(Ether):
            return "ETHERNET"
            
        return "UNKNOWN"
        
    def extract_dns_info(self, packet, analysis: PacketAnalysis):
        """Extract DNS information"""
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            
            # DNS Query
            if dns_layer.qr == 0 and dns_layer.haslayer(DNSQR):
                qname = dns_layer[DNSQR].qname.decode() if hasattr(dns_layer[DNSQR].qname, 'decode') else str(dns_layer[DNSQR].qname)
                analysis.dns_query = qname
                analysis.info = f"DNS Query: {qname}"
                
            # DNS Response
            elif dns_layer.qr == 1 and dns_layer.haslayer(DNSRR):
                answers = []
                for i in range(dns_layer.ancount):
                    rr = dns_layer.an[i]
                    if hasattr(rr, 'rdata'):
                        answers.append(str(rr.rdata))
                analysis.dns_response = answers
                analysis.info = f"DNS Response: {', '.join(answers[:3])}"
                
    def extract_http_info(self, packet, analysis: PacketAnalysis):
        """Extract HTTP information"""
        if packet.haslayer(HTTPRequest):
            http_layer = packet[HTTPRequest]
            analysis.http_method = http_layer.Method.decode() if hasattr(http_layer.Method, 'decode') else str(http_layer.Method)
            analysis.http_host = http_layer.Host.decode() if hasattr(http_layer.Host, 'decode') else str(http_layer.Host)
            analysis.http_path = http_layer.Path.decode() if hasattr(http_layer.Path, 'decode') else str(http_layer.Path)
            
            # Extract User-Agent if present
            if hasattr(http_layer, 'User_Agent'):
                analysis.http_user_agent = http_layer.User_Agent.decode() if hasattr(http_layer.User_Agent, 'decode') else str(http_layer.User_Agent)
                
            analysis.info = f"HTTP {analysis.http_method} {analysis.http_path}"
            analysis.protocol = "HTTP"
            
        elif packet.haslayer(HTTPResponse):
            http_layer = packet[HTTPResponse]
            analysis.http_status = http_layer.Status_Code
            analysis.info = f"HTTP Response: {analysis.http_status}"
            analysis.protocol = "HTTP"
            
    def calculate_payload_hash(self, packet) -> Optional[str]:
        """Calculate hash of packet payload for duplicate detection"""
        if packet.haslayer(Raw):
            try:
                import hashlib
                return hashlib.md5(bytes(packet[Raw].load)).hexdigest()[:8]
            except:
                pass
        return None
        
    def analyze_packet(self, packet) -> PacketAnalysis:
        """Enhanced packet analysis"""
        start_time = time.time()
        
        # Create analysis object
        analysis = PacketAnalysis(
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            protocol=self.get_protocol_name(packet),
            size=len(packet),
            payload_size=len(packet) - (len(packet[IP]) if packet.haslayer(IP) else 0)
        )
        
        try:
            # Ethernet layer
            if packet.haslayer(Ether):
                analysis.src_mac = packet[Ether].src
                analysis.dst_mac = packet[Ether].dst
                
                # VLAN tag detection
                if packet.haslayer(Dot1Q):
                    analysis.vlan_id = packet[Dot1Q].vlan
                    
            # IP layer
            if packet.haslayer(IP):
                ip_layer = packet[IP]
                analysis.src_ip = ip_layer.src
                analysis.dst_ip = ip_layer.dst
                analysis.ttl = ip_layer.ttl
                
                # Update IP statistics
                self.ip_stats[ip_layer.src]['sent'] += 1
                self.ip_stats[ip_layer.src]['sent_bytes'] += len(packet)
                self.ip_stats[ip_layer.dst]['received'] += 1
                self.ip_stats[ip_layer.dst]['received_bytes'] += len(packet)
                
            # IPv6 layer
            elif packet.haslayer(IPv6):
                ipv6_layer = packet[IPv6]
                analysis.src_ip = ipv6_layer.src
                analysis.dst_ip = ipv6_layer.dst
                analysis.ttl = ipv6_layer.hlim
                
            # ARP layer
            if packet.haslayer(ARP):
                arp_layer = packet[ARP]
                analysis.src_ip = arp_layer.psrc
                analysis.dst_ip = arp_layer.pdst
                analysis.src_mac = arp_layer.hwsrc
                analysis.dst_mac = arp_layer.hwdst
                op_map = {1: "who-has", 2: "is-at"}
                analysis.info = f"ARP {op_map.get(arp_layer.op, 'unknown')}: {arp_layer.psrc} -> {arp_layer.pdst}"
                
            # TCP layer
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                analysis.src_port = tcp_layer.sport
                analysis.dst_port = tcp_layer.dport
                analysis.flags = tcp_layer.flags
                analysis.seq = tcp_layer.seq
                analysis.ack = tcp_layer.ack
                analysis.window = tcp_layer.window
                
                # TCP flags analysis
                flags_info = []
                if tcp_layer.flags & 0x02:  # SYN
                    flags_info.append("SYN")
                if tcp_layer.flags & 0x10:  # ACK
                    flags_info.append("ACK")
                if tcp_layer.flags & 0x01:  # FIN
                    flags_info.append("FIN")
                if tcp_layer.flags & 0x08:  # PSH
                    flags_info.append("PSH")
                if tcp_layer.flags & 0x04:  # RST
                    flags_info.append("RST")
                if tcp_layer.flags & 0x20:  # URG
                    flags_info.append("URG")
                if tcp_layer.flags & 0x40:  # ECE
                    flags_info.append("ECE")
                if tcp_layer.flags & 0x80:  # CWR
                    flags_info.append("CWR")
                    
                analysis.flags_str = " ".join(flags_info) if flags_info else "."
                
                # TCP options parsing
                if tcp_layer.options:
                    analysis.options = {opt[0]: opt[1] for opt in tcp_layer.options if len(opt) > 1}
                    
                # Update port statistics
                self.port_stats[analysis.src_port]['source'] += 1
                self.port_stats[analysis.dst_port]['destination'] += 1
                
                # Connection tracking
                conn_key = f"{analysis.src_ip}:{analysis.src_port} -> {analysis.dst_ip}:{analysis.dst_port}"
                self.connection_stats[conn_key]['packets'] += 1
                self.connection_stats[conn_key]['bytes'] += len(packet)
                
            # UDP layer
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                analysis.src_port = udp_layer.sport
                analysis.dst_port = udp_layer.dport
                
                # Update port statistics
                self.port_stats[analysis.src_port]['source'] += 1
                self.port_stats[analysis.dst_port]['destination'] += 1
                
            # ICMP layer
            elif packet.haslayer(ICMP):
                icmp_layer = packet[ICMP]
                analysis.icmp_type = icmp_layer.type
                analysis.icmp_code = icmp_layer.code
                
                icmp_types = {
                    0: "Echo Reply", 3: "Destination Unreachable",
                    4: "Source Quench", 5: "Redirect", 8: "Echo Request",
                    11: "Time Exceeded", 12: "Parameter Problem"
                }
                analysis.info = f"ICMP {icmp_types.get(icmp_layer.type, 'Unknown')}"
                
            # Extract DNS info
            self.extract_dns_info(packet, analysis)
            
            # Extract HTTP info
            self.extract_http_info(packet, analysis)
            
            # Calculate payload hash for duplicate detection
            analysis.payload_hash = self.calculate_payload_hash(packet)
            
            # Threat detection
            self.detect_threats(analysis)
            
            # Update protocol statistics
            self.protocol_stats[analysis.protocol] += 1
            
            # Track protocol trends
            self.protocol_trends[analysis.protocol].append(time.time())
            
            # Performance tracking
            processing_time = time.time() - start_time
            self.processing_times.append(processing_time)
            
        except Exception as e:
            self.logger.error(f"Error in packet analysis: {e}")
            if self.verbose:
                print(f"{EnhancedColor.RED}[!] Analysis error: {e}{EnhancedColor.RESET}")
                
        return analysis
        
    def _analyze_packet_sync(self, packet):
        """Synchronous packet analysis (called from processor thread)"""
        try:
            analysis = self.analyze_packet(packet)
            
            # Display packet
            self.display_packet(analysis)
            
            # Store packet (with memory limit)
            if len(self.captured_packets) < CONFIG['max_packets_memory']:
                self.captured_packets.append(asdict(analysis))
                
            # Save to file
            if self.output_file:
                self.save_to_file(analysis)
                
            # Check max packets limit
            if self.max_packets > 0 and self.packet_count >= self.max_packets:
                self.running = False
                
            # Periodic stats display
            if self.stats_interval > 0:
                now = datetime.now()
                if (now - self.last_stats_time).seconds >= self.stats_interval:
                    self.display_stats()
                    self.last_stats_time = now
                    
        except Exception as e:
            self.logger.error(f"Error in packet sync: {e}")
            
    def packet_callback(self, packet):
        """Callback for packet capture"""
        if not self.running or self.paused:
            return
            
        try:
            self.packet_count += 1
            self.packet_processor.add_packet(packet)
            
        except Exception as e:
            self.drop_count += 1
            self.logger.error(f"Error in packet callback: {e}")
            
    def detect_threats(self, analysis: PacketAnalysis):
        """Run threat detection on packet"""
        # Port scan detection
        scan_alert = self.threat_detector.detect_port_scan(None, analysis)
        if scan_alert:
            self.display_alert(scan_alert)
            
        # DDoS detection
        ddos_alert = self.threat_detector.detect_ddos(None, analysis)
        if ddos_alert:
            self.display_alert(ddos_alert)
            
        # ARP spoof detection
        arp_alert = self.threat_detector.detect_arp_spoof(None, analysis)
        if arp_alert:
            self.display_alert(arp_alert)
            
    def display_alert(self, alert):
        """Display security alert"""
        severity_colors = {
            'LOW': EnhancedColor.GREEN,
            'MEDIUM': EnhancedColor.YELLOW,
            'HIGH': EnhancedColor.MAGENTA,
            'CRITICAL': EnhancedColor.RED
        }
        color = severity_colors.get(alert['severity'], EnhancedColor.WHITE)
        
        print(f"\n{color}{'!'*60}{EnhancedColor.RESET}")
        print(f"{color}[ALERT] {alert['type']}{EnhancedColor.RESET}")
        for key, value in alert.items():
            if key not in ['type', 'severity']:
                print(f"{color}  {key}: {value}{EnhancedColor.RESET}")
        print(f"{color}{'!'*60}{EnhancedColor.RESET}\n")
        
    def display_packet(self, analysis: PacketAnalysis):
        """Enhanced packet display"""
        # Protocol color coding
        protocol_colors = {
            'TCP': EnhancedColor.CYAN,
            'UDP': EnhancedColor.GREEN,
            'ICMP': EnhancedColor.YELLOW,
            'HTTP': EnhancedColor.MAGENTA,
            'HTTPS': EnhancedColor.BLUE,
            'DNS': EnhancedColor.YELLOW,
            'ARP': EnhancedColor.RED,
            'DHCP': EnhancedColor.GREEN,
            'IPv6': EnhancedColor.CYAN
        }
        
        color = protocol_colors.get(analysis.protocol, EnhancedColor.WHITE)
        
        # Compact mode for high volume
        if self.packet_count % 100 == 0 and not self.verbose:
            print(f"{EnhancedColor.BOLD}[{self.packet_count}] {analysis.timestamp} - {color}{analysis.protocol}{EnhancedColor.RESET} {analysis.src_ip or ''}:{analysis.src_port or ''} -> {analysis.dst_ip or ''}:{analysis.dst_port or ''} ({analysis.size} bytes)")
            return
            
        # Detailed output
        print(f"\n{EnhancedColor.BOLD}{EnhancedColor.WHITE}[{self.packet_count}] {analysis.timestamp}{EnhancedColor.RESET}")
        print(f"  {EnhancedColor.BOLD}Protocol:{EnhancedColor.RESET} {color}{analysis.protocol}{EnhancedColor.RESET}")
        
        if analysis.src_ip and analysis.dst_ip:
            src_str = f"{analysis.src_ip}:{analysis.src_port}" if analysis.src_port else analysis.src_ip
            dst_str = f"{analysis.dst_ip}:{analysis.dst_port}" if analysis.dst_port else analysis.dst_ip
            print(f"  {EnhancedColor.BOLD}Source:{EnhancedColor.RESET} {src_str}")
            print(f"  {EnhancedColor.BOLD}Destination:{EnhancedColor.RESET} {dst_str}")
            
        if analysis.src_mac and analysis.dst_mac:
            print(f"  {EnhancedColor.BOLD}MAC:{EnhancedColor.RESET} {analysis.src_mac} -> {analysis.dst_mac}")
            if analysis.vlan_id:
                print(f"  {EnhancedColor.BOLD}VLAN:{EnhancedColor.RESET} {analysis.vlan_id}")
                
        if analysis.flags_str:
            print(f"  {EnhancedColor.BOLD}TCP Flags:{EnhancedColor.RESET} {analysis.flags_str}")
            if analysis.seq:
                print(f"  {EnhancedColor.BOLD}Seq/Ack:{EnhancedColor.RESET} {analysis.seq}/{analysis.ack}")
                
        if analysis.info:
            print(f"  {EnhancedColor.BOLD}Info:{EnhancedColor.RESET} {analysis.info}")
            
        # DNS info
        if analysis.dns_query:
            print(f"  {EnhancedColor.BOLD}DNS Query:{EnhancedColor.RESET} {analysis.dns_query}")
        if analysis.dns_response:
            print(f"  {EnhancedColor.BOLD}DNS Response:{EnhancedColor.RESET} {', '.join(analysis.dns_response[:3])}")
            
        # HTTP info
        if analysis.http_method:
            print(f"  {EnhancedColor.BOLD}HTTP Method:{EnhancedColor.RESET} {analysis.http_method}")
        if analysis.http_status:
            print(f"  {EnhancedColor.BOLD}HTTP Status:{EnhancedColor.RESET} {analysis.http_status}")
            
        print(f"  {EnhancedColor.BOLD}Size:{EnhancedColor.RESET} {analysis.size} bytes (payload: {analysis.payload_size})")
        
        if analysis.payload_hash:
            print(f"  {EnhancedColor.BOLD}Payload Hash:{EnhancedColor.RESET} {analysis.payload_hash}")
            
    def display_stats(self):
        """Display live statistics"""
        now = datetime.now()
        duration = now - self.start_time
        pps = self.packet_count / max(duration.total_seconds(), 1)
        
        print(f"\n{EnhancedColor.BOLD}{EnhancedColor.CYAN}[STATS] {now.strftime('%H:%M:%S')}{EnhancedColor.RESET}")
        print(f"  Packets: {self.packet_count} | Rate: {pps:.2f} pps | Drops: {self.drop_count}")
        
        # Top 5 protocols
        top_protos = sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True)[:5]
        if top_protos:
            print(f"  Top Protocols: {', '.join([f'{p}({c})' for p, c in top_protos])}")
            
    def save_to_file(self, analysis: PacketAnalysis):
        """Enhanced file saving"""
        try:
            # Rotate file if too large
            if os.path.exists(self.output_file) and os.path.getsize(self.output_file) > CONFIG['buffer_size']:
                base, ext = os.path.splitext(self.output_file)
                os.rename(self.output_file, f"{base}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}")
                
            with open(self.output_file, 'a') as f:
                json.dump(asdict(analysis), f, default=str)
                f.write('\n')
                
        except Exception as e:
            self.logger.error(f"Error saving to file: {e}")
            
    def generate_report(self):
        """Enhanced report generation"""
        print(f"\n{EnhancedColor.BOLD}{EnhancedColor.CYAN}{'='*70}{EnhancedColor.RESET}")
        print(f"{EnhancedColor.BOLD}{EnhancedColor.CYAN}CAPTURE STATISTICS REPORT{EnhancedColor.RESET}")
        print(f"{EnhancedColor.BOLD}{EnhancedColor.CYAN}{'='*70}{EnhancedColor.RESET}")
        
        duration = datetime.now() - self.start_time
        pps = self.packet_count / max(duration.total_seconds(), 1)
        
        print(f"\n{EnhancedColor.BOLD}Capture Duration:{EnhancedColor.RESET} {duration}")
        print(f"{EnhancedColor.BOLD}Total Packets:{EnhancedColor.RESET} {self.packet_count}")
        print(f"{EnhancedColor.BOLD}Average Rate:{EnhancedColor.RESET} {pps:.2f} packets/sec")
        print(f"{EnhancedColor.BOLD}Dropped Packets:{EnhancedColor.RESET} {self.drop_count}")
        print(f"{EnhancedColor.BOLD}Processing Time Avg:{EnhancedColor.RESET} {sum(self.processing_times[-100:])/max(len(self.processing_times[-100:]),1):.6f} sec")
        
        # Protocol Statistics
        print(f"\n{EnhancedColor.BOLD}{EnhancedColor.YELLOW}Protocol Statistics:{EnhancedColor.RESET}")
        print(f"{'-'*50}")
        total = sum(self.protocol_stats.values())
        for protocol, count in sorted(self.protocol_stats.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            bar = '█' * int(percentage / 2)
            print(f"{protocol:15} {count:8} packets ({percentage:6.2f}%) {bar}")
            
        # Top Talkers
        print(f"\n{EnhancedColor.BOLD}{EnhancedColor.YELLOW}Top Talkers (by packets):{EnhancedColor.RESET}")
        print(f"{'-'*50}")
        sorted_ips = sorted(self.ip_stats.items(), key=lambda x: x[1]['sent'] + x[1]['received'], reverse=True)[:10]
        for ip, stats in sorted_ips:
            total_pkts = stats['sent'] + stats['received']
            total_bytes = stats['sent_bytes'] + stats['received_bytes']
            print(f"{ip:20} {total_pkts:8} pkts ({self.format_bytes(total_bytes):>10})")
            
        # Port Statistics
        print(f"\n{EnhancedColor.BOLD}{EnhancedColor.YELLOW}Top Ports:{EnhancedColor.RESET}")
        print(f"{'-'*50}")
        top_src_ports = sorted(self.port_stats.items(), key=lambda x: x[1].get('source', 0), reverse=True)[:5]
        top_dst_ports = sorted(self.port_stats.items(), key=lambda x: x[1].get('destination', 0), reverse=True)[:5]
        
        print("Source Ports:")
        for port, stats in top_src_ports:
            if stats.get('source', 0) > 0:
                print(f"  {port:8} -> {stats['source']:6} packets")
                
        print("Destination Ports:")
        for port, stats in top_dst_ports:
            if stats.get('destination', 0) > 0:
                print(f"  {port:8} -> {stats['destination']:6} packets")
                
        # Active Connections
        print(f"\n{EnhancedColor.BOLD}{EnhancedColor.YELLOW}Active Connections:{EnhancedColor.RESET}")
        print(f"{'-'*70}")
        for conn, stats in list(self.connection_stats.items())[:10]:
            print(f"{conn:60} {stats['packets']:6} pkts ({self.format_bytes(stats['bytes']):>10})")
            
        # Security Alerts
        if self.threat_detector.alert_history:
            print(f"\n{EnhancedColor.BOLD}{EnhancedColor.RED}Security Alerts ({len(self.threat_detector.alert_history)}):{EnhancedColor.RESET}")
            print(f"{'-'*50}")
            for alert in self.threat_detector.alert_history[-10:]:  # Last 10 alerts
                severity_color = {
                    'LOW': EnhancedColor.GREEN,
                    'MEDIUM': EnhancedColor.YELLOW,
                    'HIGH': EnhancedColor.MAGENTA,
                    'CRITICAL': EnhancedColor.RED
                }.get(alert['severity'], EnhancedColor.WHITE)
                
                print(f"{severity_color}[{alert['severity']}] {alert['type']} - {alert.get('src_ip', alert.get('dst_ip', ''))}{EnhancedColor.RESET}")
                
        # Export to CSV
        if self.output_file and PANDAS_AVAILABLE:
            self.export_to_csv()
            
    def format_bytes(self, bytes_val):
        """Format bytes to human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if bytes_val < 1024.0:
                return f"{bytes_val:.1f} {unit}"
            bytes_val /= 1024.0
        return f"{bytes_val:.1f} TB"
        
    def export_to_csv(self):
        """Export captured data to CSV"""
        try:
            csv_file = self.output_file.replace('.json', '.csv')
            if csv_file == self.output_file:
                csv_file += '.csv'
                
            df = pd.DataFrame(self.captured_packets)
            
            # Convert timestamp to datetime for better analysis
            if 'timestamp' in df.columns:
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                
            # Add derived columns
            if 'src_ip' in df.columns and 'dst_ip' in df.columns:
                df['communication'] = df['src_ip'] + ':' + df['src_port'].astype(str) + ' -> ' + df['dst_ip'] + ':' + df['dst_port'].astype(str)
                
            df.to_csv(csv_file, index=False)
            print(f"\n{EnhancedColor.GREEN}[+] Data exported to {csv_file}{EnhancedColor.RESET}")
            
            # Generate summary statistics
            summary_file = self.output_file.replace('.json', '_summary.txt')
            with open(summary_file, 'w') as f:
                f.write(f"Packet Capture Summary\n")
                f.write(f"{'='*50}\n")
                f.write(f"Total Packets: {len(df)}\n")
                f.write(f"Protocol Distribution:\n{df['protocol'].value_counts().to_string()}\n")
                f.write(f"\nTop Source IPs:\n{df['src_ip'].value_counts().head(10).to_string()}\n")
                f.write(f"\nTop Destination IPs:\n{df['dst_ip'].value_counts().head(10).to_string()}\n")
                
            print(f"{EnhancedColor.GREEN}[+] Summary exported to {summary_file}{EnhancedColor.RESET}")
            
        except Exception as e:
            self.logger.error(f"Error exporting to CSV: {e}")
            print(f"{EnhancedColor.RED}[!] Error exporting to CSV: {e}{EnhancedColor.RESET}")
            
    def start_capture(self):
        """Enhanced capture start"""
        print(f"{EnhancedColor.BOLD}{EnhancedColor.GREEN}[+] Starting enhanced packet capture...{EnhancedColor.RESET}")
        print(f"{EnhancedColor.BOLD}Interface:{EnhancedColor.RESET} {self.interface or 'All'}")
        print(f"{EnhancedColor.BOLD}Filter:{EnhancedColor.RESET} {self.filter_expr or 'None'}")
        print(f"{EnhancedColor.BOLD}Output:{EnhancedColor.RESET} {self.output_file or 'None'}")
        print(f"{EnhancedColor.BOLD}Max Packets:{EnhancedColor.RESET} {self.max_packets or 'Unlimited'}")
        print(f"{EnhancedColor.BOLD}Verbose:{EnhancedColor.RESET} {self.verbose}")
        print(f"{EnhancedColor.YELLOW}[!] Press Ctrl+C to stop capture{EnhancedColor.RESET}")
        print(f"{EnhancedColor.YELLOW}[!] Press 'p' to pause/resume{EnhancedColor.RESET}")
        
        # Set up signal handler
        signal.signal(signal.SIGINT, self.signal_handler)
        
        # Start keyboard listener for pause
        import threading
        def keyboard_listener():
            while self.running:
                try:
                    if sys.stdin.read(1).lower() == 'p':
                        self.paused = not self.paused
                        status = "PAUSED" if self.paused else "RESUMED"
                        print(f"{EnhancedColor.YELLOW}[!] Capture {status}{EnhancedColor.RESET}")
                except:
                    pass
                    
        listener_thread = threading.Thread(target=keyboard_listener, daemon=True)
        listener_thread.start()
        
        try:
            # Start sniffing with enhanced parameters
            sniff(
                iface=self.interface,
                filter=self.filter_expr,
                prn=self.packet_callback,
                store=False,
                count=self.max_packets if self.max_packets > 0 else None,
                timeout=CONFIG['timeout']
            )
        except PermissionError:
            print(f"{EnhancedColor.RED}[!] Permission denied. Try running with sudo/administrator privileges{EnhancedColor.RESET}")
            sys.exit(1)
        except Scapy_Exception as e:
            print(f"{EnhancedColor.RED}[!] Scapy error: {e}{EnhancedColor.RESET}")
            sys.exit(1)
        except Exception as e:
            print(f"{EnhancedColor.RED}[!] Error during capture: {e}{EnhancedColor.RESET}")
            sys.exit(1)

def list_interfaces():
    """Enhanced interface listing"""
    print(f"{EnhancedColor.BOLD}{EnhancedColor.CYAN}Available Network Interfaces:{EnhancedColor.RESET}")
    print(f"{EnhancedColor.BOLD}{EnhancedColor.CYAN}{'='*60}{EnhancedColor.RESET}")
    
    interfaces = get_if_list()
    detailed_interfaces = []
    
    for iface in interfaces:
        try:
            # Get interface details
            mac = get_if_hwaddr(iface)
            ip = get_if_addr(iface)
            status = "UP" if iface in get_working_ifaces() else "DOWN"
            detailed_interfaces.append((iface, ip, mac, status))
        except:
            detailed_interfaces.append((iface, "N/A", "N/A", "UNKNOWN"))
            
    for i, (iface, ip, mac, status) in enumerate(detailed_interfaces, 1):
        status_color = EnhancedColor.GREEN if status == "UP" else EnhancedColor.RED
        print(f"{i:2}. {EnhancedColor.BOLD}{iface:10}{EnhancedColor.RESET} IP: {ip:15} MAC: {mac:17} Status: {status_color}{status}{EnhancedColor.RESET}")
        
    print(f"\n{EnhancedColor.YELLOW}Note: Use interface name (not number) with -i option{EnhancedColor.RESET}")
    return interfaces

def main():
    """Enhanced main function"""
    parser = argparse.ArgumentParser(
        description="Enhanced Network Packet Sniffer and Analyzer v2.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -i eth0                     # Basic capture
  %(prog)s -i eth0 -v                   # Verbose mode
  %(prog)s -i eth0 -f "tcp port 80"    # HTTP traffic only
  %(prog)s -i eth0 -c 1000              # Capture 1000 packets
  %(prog)s -i eth0 -o capture.json      # Save to file
  %(prog)s -i eth0 -s 5                 # Stats every 5 seconds
  %(prog)s --list-interfaces            # List interfaces
  %(prog)s -i eth0 --no-color           # Disable colors
        """
    )
    
    parser.add_argument("-i", "--interface", help="Network interface to capture on")
    parser.add_argument("-f", "--filter", help="BPF filter expression (e.g., 'tcp port 80')")
    parser.add_argument("-c", "--count", type=int, default=0, help="Number of packets to capture (0 for unlimited)")
    parser.add_argument("-o", "--output", help="Output file for captured packets (JSON format)")
    parser.add_argument("-s", "--stats", type=int, default=10, help="Statistics display interval in seconds")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("-l", "--list-interfaces", action="store_true", help="List available network interfaces")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    parser.add_argument("--max-memory", type=int, default=10000, help="Max packets to keep in memory")
    parser.add_argument("--timeout", type=int, default=60, help="Capture timeout in seconds")
    
    args = parser.parse_args()
    
    # Update configuration
    if args.max_memory:
        CONFIG['max_packets_memory'] = args.max_memory
    if args.timeout:
        CONFIG['timeout'] = args.timeout
        
    # Handle no-color option
    if args.no_color and not COLORAMA_AVAILABLE:
        # Override color class with empty strings
        for attr in dir(EnhancedColor):
            if not attr.startswith('_'):
                setattr(EnhancedColor, attr, '')
                
    if args.list_interfaces:
        list_interfaces()
        sys.exit(0)
        
    if not args.interface:
        print(f"{EnhancedColor.YELLOW}[!] No interface specified. Use -i option or --list-interfaces to see available interfaces{EnhancedColor.RESET}")
        print(f"{EnhancedColor.YELLOW}[!] Example: sudo %(prog)s -i eth0{EnhancedColor.RESET}")
        sys.exit(1)
        
    # Create analyzer instance
    analyzer = PacketAnalyzer(
        interface=args.interface,
        filter_expr=args.filter,
        output_file=args.output,
        verbose=args.verbose,
        stats_interval=args.stats,
        max_packets=args.count
    )
    
    # Start capture
    analyzer.start_capture()

if __name__ == "__main__":
    main()
