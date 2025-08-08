from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

def analyze_packet(packet):
    # Only process packets with an IP layer
    if IP in packet:
        print("=" * 60)
        print("📦 Packet Captured")

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        print(f"➡️  Source IP: {src_ip}")
        print(f"⬅️  Destination IP: {dst_ip}")

        # Detect protocol
        if packet.haslayer(TCP):
            proto = "TCP"
        elif packet.haslayer(UDP):
            proto = "UDP"
        elif packet.haslayer(ICMP):
            proto = "ICMP"
        else:
            proto = "Other"
        print(f"🔀 Protocol: {proto}")

        # Show payload if present
        if packet.haslayer(Raw):
            raw_data = packet[Raw].load
            print(f"📄 Payload: {raw_data[:100]}")  # only first 100 bytes
        else:
            print("📄 Payload: None")

print("[*] Starting packet capture on Wi-Fi... Press Ctrl+C to stop.")
sniff(iface="Wi-Fi", prn=analyze_packet, store=False, filter="ip")
