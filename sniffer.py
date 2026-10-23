"""Summarize IP and transport metadata from an offline classic PCAP capture."""

from __future__ import annotations

import argparse
import csv
import json
import socket
import struct
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Any


PCAP_FORMATS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}
ETHERNET = 1
VLAN_TYPES = {0x8100, 0x88A8, 0x9100}
IPV6_EXTENSIONS = {0, 43, 60, 135, 139, 140}


@dataclass
class Flow:
    protocol: str
    source: str
    source_port: int | None
    destination: str
    destination_port: int | None
    packets: int = 0
    wire_bytes: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    tcp_syn: int = 0
    tcp_fin: int = 0
    tcp_rst: int = 0

    def observe(self, timestamp: float, wire_bytes: int, tcp_flags: int | None) -> None:
        if self.packets == 0:
            self.first_seen = timestamp
        self.last_seen = timestamp
        self.packets += 1
        self.wire_bytes += wire_bytes
        if tcp_flags is not None:
            self.tcp_fin += bool(tcp_flags & 0x01)
            self.tcp_syn += bool(tcp_flags & 0x02)
            self.tcp_rst += bool(tcp_flags & 0x04)


def parse_transport(
    protocol_number: int, payload: bytes, can_read_transport: bool
) -> tuple[str, int | None, int | None, int | None]:
    protocol_names = {1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6"}
    protocol = protocol_names.get(protocol_number, f"IP-{protocol_number}")
    src_port = dst_port = tcp_flags = None
    if can_read_transport and protocol_number in (6, 17) and len(payload) >= 4:
        src_port, dst_port = struct.unpack_from("!HH", payload)
        if protocol_number == 6 and len(payload) >= 14:
            tcp_flags = payload[13]
    return protocol, src_port, dst_port, tcp_flags


def parse_ipv4(packet: bytes) -> tuple[str, str, str, int | None, int | None, int | None] | None:
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    header_length = (packet[0] & 0x0F) * 4
    total_length = struct.unpack_from("!H", packet, 2)[0]
    if header_length < 20 or total_length < header_length or len(packet) < header_length:
        return None
    fragment = struct.unpack_from("!H", packet, 6)[0]
    fragment_offset = fragment & 0x1FFF
    protocol_number = packet[9]
    src = socket.inet_ntop(socket.AF_INET, packet[12:16])
    dst = socket.inet_ntop(socket.AF_INET, packet[16:20])
    ip_payload = packet[header_length:min(len(packet), total_length)]
    protocol, src_port, dst_port, tcp_flags = parse_transport(
        protocol_number, ip_payload, fragment_offset == 0
    )
    return protocol, src, dst, src_port, dst_port, tcp_flags


def parse_ipv6(packet: bytes) -> tuple[str, str, str, int | None, int | None, int | None] | None:
    if len(packet) < 40 or packet[0] >> 4 != 6:
        return None
    payload_length = struct.unpack_from("!H", packet, 4)[0]
    payload_end = min(len(packet), 40 + payload_length) if payload_length else len(packet)
    next_header = packet[6]
    src = socket.inet_ntop(socket.AF_INET6, packet[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, packet[24:40])
    offset = 40
    first_fragment = True
    extension_count = 0

    while next_header in IPV6_EXTENSIONS or next_header in (44, 51):
        extension_count += 1
        if extension_count > 16 or offset + 2 > payload_end:
            return None
        following_header = packet[offset]
        if next_header == 44:
            if offset + 8 > payload_end:
                return None
            fragment_field = struct.unpack_from("!H", packet, offset + 2)[0]
            first_fragment = (fragment_field & 0xFFF8) == 0
            extension_length = 8
        elif next_header == 51:
            extension_length = (packet[offset + 1] + 2) * 4
        else:
            extension_length = (packet[offset + 1] + 1) * 8
        if extension_length <= 0 or offset + extension_length > payload_end:
            return None
        offset += extension_length
        next_header = following_header

    protocol, src_port, dst_port, tcp_flags = parse_transport(
        next_header, packet[offset:payload_end], first_fragment
    )
    return protocol, src, dst, src_port, dst_port, tcp_flags


def parse_ethernet(
    frame: bytes,
) -> tuple[bool, tuple[str, str, str, int | None, int | None, int | None] | None]:
    if len(frame) < 14:
        return True, None
    ether_type = struct.unpack_from("!H", frame, 12)[0]
    offset = 14
    while ether_type in VLAN_TYPES:
        if len(frame) < offset + 4:
            return True, None
        ether_type = struct.unpack_from("!H", frame, offset + 2)[0]
        offset += 4
    network_packet = frame[offset:]
    if ether_type == 0x0800:
        return True, parse_ipv4(network_packet)
    if ether_type == 0x86DD:
        return True, parse_ipv6(network_packet)
    return False, None


def read_exact(source: BinaryIO, length: int, description: str) -> bytes:
    value = source.read(length)
    if len(value) != length:
        raise ValueError(f"Capture is truncated while reading {description}.")
    return value


def analyze_capture(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"Capture file does not exist: {path}")
    flows: dict[tuple[str, str, int | None, str, int | None], Flow] = {}
    talkers: dict[str, dict[str, int]] = defaultdict(
        lambda: {"sent_packets": 0, "received_packets": 0, "sent_wire_bytes": 0, "received_wire_bytes": 0}
    )
    protocols: Counter[str] = Counter()
    packets = non_ip = malformed = 0
    first_timestamp: float | None = None
    last_timestamp: float | None = None

    with path.open("rb") as capture:
        global_header = read_exact(capture, 24, "the PCAP global header")
        magic = global_header[:4]
        if magic not in PCAP_FORMATS:
            raise ValueError("Unsupported capture format; save the file as a classic .pcap capture.")
        byte_order, timestamp_base = PCAP_FORMATS[magic]
        major, _minor, _zone, _accuracy, snap_length, link_type = struct.unpack(
            byte_order + "HHiIII", global_header[4:]
        )
        if major != 2 or snap_length == 0:
            raise ValueError("Invalid PCAP global header.")
        if (link_type & 0xFFFF) != ETHERNET:
            raise ValueError("Only Ethernet-link-layer PCAP captures are supported.")

        record_number = 0
        while True:
            record_header = capture.read(16)
            if not record_header:
                break
            if len(record_header) != 16:
                raise ValueError(f"Capture is truncated at record {record_number + 1} header.")
            seconds, fraction, captured_length, wire_length = struct.unpack(
                byte_order + "IIII", record_header
            )
            record_number += 1
            if fraction >= timestamp_base or captured_length > snap_length or wire_length < captured_length:
                raise ValueError(f"PCAP record {record_number} has invalid length or timestamp fields.")
            frame = read_exact(capture, captured_length, f"record {record_number} data")
            timestamp = seconds + fraction / timestamp_base
            first_timestamp = timestamp if first_timestamp is None else min(first_timestamp, timestamp)
            last_timestamp = timestamp if last_timestamp is None else max(last_timestamp, timestamp)
            is_ip, parsed = parse_ethernet(frame)
            if parsed is None:
                if is_ip:
                    malformed += 1
                else:
                    non_ip += 1
                continue

            protocol, source, destination, source_port, destination_port, tcp_flags = parsed
            packets += 1
            protocols[protocol] += 1
            talkers[source]["sent_packets"] += 1
            talkers[source]["sent_wire_bytes"] += wire_length
            talkers[destination]["received_packets"] += 1
            talkers[destination]["received_wire_bytes"] += wire_length
            key = (protocol, source, source_port, destination, destination_port)
            if key not in flows:
                flows[key] = Flow(protocol, source, source_port, destination, destination_port)
            flows[key].observe(timestamp, wire_length, tcp_flags)

    ordered_flows = sorted(flows.values(), key=lambda flow: (-flow.packets, -flow.wire_bytes, flow.source))
    ordered_talkers = sorted(
        (
            {"address": address, **counts, "total_wire_bytes": counts["sent_wire_bytes"] + counts["received_wire_bytes"]}
            for address, counts in talkers.items()
        ),
        key=lambda item: (-item["total_wire_bytes"], item["address"]),
    )
    return {
        "capture": path.name,
        "records": record_number,
        "packets": packets,
        "non_ip_packets": non_ip,
        "malformed_packets": malformed,
        "flows": len(ordered_flows),
        "first_timestamp": first_timestamp,
        "last_timestamp": last_timestamp,
        "duration_seconds": (last_timestamp - first_timestamp) if first_timestamp is not None else 0.0,
        "protocols": dict(sorted(protocols.items())),
        "top_talkers": ordered_talkers[:20],
        "_ordered_flows": ordered_flows,
    }


def write_flows(path: Path, flows: list[Flow]) -> None:
    fieldnames = (
        "protocol", "source", "source_port", "destination", "destination_port", "packets",
        "wire_bytes", "first_seen", "last_seen", "tcp_syn", "tcp_fin", "tcp_rst",
    )
    with path.open("w", encoding="utf-8", newline="") as destination:
        writer = csv.DictWriter(destination, fieldnames=fieldnames)
        writer.writeheader()
        for flow in flows:
            writer.writerow({name: getattr(flow, name) for name in fieldnames})


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Summarize IP flows in an offline classic Ethernet PCAP without exporting packet payloads."
    )
    parser.add_argument("capture", type=Path, help="Input classic .pcap file (not pcapng).")
    parser.add_argument("--flows-out", type=Path, default=Path("flows.csv"), help="Destination CSV for directed flows.")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.capture.resolve() == args.flows_out.resolve():
            raise ValueError("Flow output must not overwrite the capture file.")
        summary = analyze_capture(args.capture)
        args.flows_out.parent.mkdir(parents=True, exist_ok=True)
        write_flows(args.flows_out, summary.pop("_ordered_flows"))
    except (OSError, ValueError, struct.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(summary, indent=2))
    print(f"Wrote directed flow records to {args.flows_out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
