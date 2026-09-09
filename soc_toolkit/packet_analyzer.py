import time
import tempfile
from collections import Counter
from typing import List, Dict, Any, Optional

try:
    from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Ether
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False

from .db import insert_packet_summary, get_packets_summary

# In-memory buffer of recently processed packets for fast analytics
packet_buffer: List[Dict[str, Any]] = []

def parse_packet_scapy(pkt) -> Optional[Dict[str, Any]]:
    try:
        timestamp = float(pkt.time) if hasattr(pkt, 'time') else time.time()
        size = len(pkt)
        proto = "OTHER"
        src_ip = None
        dst_ip = None
        src_port = None
        dst_port = None
        info = ""

        if pkt.haslayer(ARP):
            proto = "ARP"
            arp = pkt.getlayer(ARP)
            src_ip = arp.psrc
            dst_ip = arp.pdst
            info = f"ARP {'Request' if arp.op==1 else 'Reply'} {src_ip} -> {dst_ip}"
        elif pkt.haslayer(IP):
            ip = pkt.getlayer(IP)
            src_ip = ip.src
            dst_ip = ip.dst
            proto = "IP"

            if pkt.haslayer(TCP):
                tcp = pkt.getlayer(TCP)
                src_port = tcp.sport
                dst_port = tcp.dport
                if dst_port == 80 or src_port == 80:
                    proto = "HTTP"
                elif dst_port == 443 or src_port == 443:
                    proto = "HTTPS"
                elif dst_port == 1883 or src_port == 1883:
                    proto = "MQTT"
                elif dst_port == 21 or src_port == 21:
                    proto = "FTP"
                elif dst_port == 23 or src_port == 23:
                    proto = "TELNET"
                else:
                    proto = "TCP"
                flags = tcp.flags
                info = f"TCP {src_port} -> {dst_port} [{flags}]"
            elif pkt.haslayer(UDP):
                udp = pkt.getlayer(UDP)
                src_port = udp.sport
                dst_port = udp.dport
                if pkt.haslayer(DNS):
                    proto = "DNS"
                    dns = pkt.getlayer(DNS)
                    qname = dns.qd.qname.decode('utf-8', errors='ignore') if dns.qd else ""
                    info = f"DNS Query {qname}"
                else:
                    proto = "UDP"
                    info = f"UDP {src_port} -> {dst_port}"
            elif pkt.haslayer(ICMP):
                proto = "ICMP"
                info = f"ICMP Echo/Reply {src_ip} -> {dst_ip}"
        
        parsed = {
            "timestamp": timestamp,
            "protocol": proto,
            "src_ip": src_ip or "0.0.0.0",
            "dst_ip": dst_ip or "0.0.0.0",
            "src_port": src_port,
            "dst_port": dst_port,
            "packet_size": size,
            "info": info or f"{proto} Packet ({size} bytes)"
        }
        return parsed
    except Exception as e:
        return None

def analyze_pcap_bytes(pcap_bytes: bytes) -> Dict[str, Any]:
    if not HAS_SCAPY:
        return {"error": "Scapy library unavailable for PCAP decoding."}
    
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(pcap_bytes)
        tmp_path = tmp.name

    try:
        packets = rdpcap(tmp_path)
        parsed_list = []
        for pkt in packets:
            p = parse_packet_scapy(pkt)
            if p:
                parsed_list.append(p)
                insert_packet_summary(
                    protocol=p["protocol"],
                    src_ip=p["src_ip"],
                    dst_ip=p["dst_ip"],
                    src_port=p["src_port"],
                    dst_port=p["dst_port"],
                    packet_size=p["packet_size"],
                    info=p["info"]
                )
                packet_buffer.append(p)
        
        return aggregate_packet_data(parsed_list)
    except Exception as e:
        return {"error": f"Failed to parse PCAP file: {str(e)}"}

def aggregate_packet_data(packets: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    if packets is None:
        packets = get_packets_summary(limit=200)

    total_packets = len(packets)
    total_bytes = sum(p.get("packet_size", 0) for p in packets)
    
    protocols = Counter(p.get("protocol", "OTHER") for p in packets)
    src_ips = Counter(p.get("src_ip", "0.0.0.0") for p in packets)
    dst_ips = Counter(p.get("dst_ip", "0.0.0.0") for p in packets)
    
    conversations = Counter(
        f"{p.get('src_ip')} -> {p.get('dst_ip')}" for p in packets if p.get('src_ip') and p.get('dst_ip')
    )

    top_talkers = [
        {"ip": ip, "count": count} for ip, count in src_ips.most_common(5)
    ]
    
    top_conversations = [
        {"pair": pair, "count": count} for pair, count in conversations.most_common(5)
    ]

    return {
        "total_packets": total_packets,
        "total_bytes": total_bytes,
        "protocol_breakdown": dict(protocols),
        "top_talkers": top_talkers,
        "top_conversations": top_conversations,
        "packets": packets[:50]
    }
