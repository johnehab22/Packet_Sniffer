from scapy.all import sniff, IP, Raw
import socket
from datetime import datetime

# Optional: log to a file
LOG_TO_FILE = True
LOG_FILE = "packets_log.txt"

def get_protocol_name(proto_num):
    try:
        if proto_num == 6:
            return "TCP"
        elif proto_num == 17:
            return "UDP"
        elif proto_num == 1:
            return "ICMP"
        else:
            return str(proto_num)
    except Exception:
        return str(proto_num)

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        proto = get_protocol_name(ip_layer.proto)

        print(f"[{datetime.now().strftime('%H:%M:%S')}]")
        print(f"Source IP:      {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol:       {proto}")

        if Raw in packet:
            try:
                payload = packet[Raw].load.decode('utf-8', errors='replace')
                print(f"Payload:\n{payload}")
            except Exception as e:
                print(f"Payload could not be decoded: {e}")

        print("\n" + "="*60 + "\n")

        if LOG_TO_FILE:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {src_ip} -> {dst_ip} | Protocol: {proto}\n")
                if Raw in packet:
                    f.write(f"Payload:\n{payload}\n")
                f.write("="*60 + "\n")

print("Starting network sniffer with analysis... Press Ctrl+C to stop.")
sniff(filter="ip", prn=packet_callback, store=0)
