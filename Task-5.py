from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP

def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        protocol_name = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol, "Other")

        print(f"📡 Packet Captured: {src_ip} → {dst_ip} | Protocol: {protocol_name}")

        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[TCP].payload) if packet.haslayer(TCP) else bytes(packet[UDP].payload)
            if payload:
                print(f"🔍 Payload: {payload[:50]}...")  # Show first 50 bytes of payload

# Start sniffing packets (CTRL+C to stop)
print("🔴 Sniffing network traffic... Press CTRL+C to stop.")
sniff(filter="ip", prn=packet_callback, store=False)
