import socket
import struct
import sys

def format_mac(bytes_addr):
    return ':'.join(f'{b:02x}' for b in bytes_addr)

def parse_ip_header(raw_data):
    version_header_len = raw_data[0]
    version = version_header_len >> 4
    header_len = (version_header_len & 15) * 4
    ttl, proto, src, target = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])
    src_ip = socket.inet_ntoa(src)
    target_ip = socket.inet_ntoa(target)
    return version, header_len, ttl, proto, src_ip, target_ip, raw_data[header_len:]

def main():
    print("=" * 60)
    print("📡 Cybersecurity Network Packet Inspector")
    print("=" * 60)
    print("Press Ctrl+C to stop sniffing...\n")

    try:
        # Create raw socket (Requires Administrator / Root privileges)
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind(("0.0.0.0", 0))
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except PermissionError:
        print("⚠️  Warning: Raw sockets require Administrator privileges.")
        print("Running packet parser simulation mode...")
        print("[+] Simulating captured IP Packet: 192.168.1.50:443 -> 192.168.1.10:52134 (Protocol: TCP)")
        print("[+] Header Length: 20 bytes | TTL: 64 | Payload Length: 128 bytes")
        return

    try:
        packet_count = 0
        while packet_count < 10:
            raw_data, _ = sniffer.recvfrom(65535)
            version, header_len, ttl, proto, src_ip, target_ip, payload = parse_ip_header(raw_data)
            packet_count += 1
            proto_name = "TCP" if proto == 6 else ("UDP" if proto == 17 else f"Protocol-{proto}")
            print(f"[{packet_count:02d}] {src_ip} -> {target_ip} | Proto: {proto_name:<6} | TTL: {ttl} | Payload: {len(payload)} bytes")
    except KeyboardInterrupt:
        print("\n[!] Packet capture stopped by user.")

if __name__ == "__main__":
    main()
