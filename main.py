from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
from datetime import datetime

log_file = "packet_log.txt"

def process_packet(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto
        payload = packet[IP].payload
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        
        if proto == 1:
            proto_name = "ICMP"
        elif proto == 6:
            proto_name = "TCP"
        elif proto == 17:
            proto_name = "UDP"
        else:
            proto_name = "Other"

        
        packet_details = (
            f"Timestamp: {timestamp}\n"
            f"Source IP: {src_ip}\n"
            f"Destination IP: {dst_ip}\n"
            f"Protocol: {proto_name}\n"
            f"Payload: {payload}\n"
            f"\n{'-'*50}\n\n"
        )

        
        with open(log_file, "a") as f:
            f.write(packet_details)


sniff(prn=process_packet, store=False)