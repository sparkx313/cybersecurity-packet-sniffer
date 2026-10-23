# Offline PCAP Flow Analyzer

Analyze a classic Ethernet `.pcap` file you already have and export directed IP-flow metadata to CSV. The parser supports IPv4, IPv6, VLAN-tagged Ethernet, TCP, UDP, and other IP protocol numbers. The summary includes protocol counts, capture duration, top talkers, and TCP SYN/FIN/RST counts.

The tool only reads the capture file you select. It does not open raw sockets, capture live traffic, or save packet payloads.

## Requirements

- Python 3.10 or newer
- A classic Ethernet-link-layer `.pcap` file

The analyzer uses the Python standard library; no third-party packages are needed. If your capture is pcapng, export it as classic PCAP from Wireshark first.

## Use

Capture traffic through your approved network-monitoring process and save it as `capture.pcap`. Then run:

```bash
python sniffer.py capture.pcap --flows-out reports/flows.csv
```

The command prints a JSON summary and writes one row per directed flow with endpoint addresses, ports when available, packet count, original on-wire byte count, first/last timestamps, and TCP control-flag counts. The CSV contains metadata only; application payloads are not decoded or exported.

## Supported capture details

- Supports classic PCAP with little/big endian microsecond or nanosecond timestamps and Ethernet link type.
- Parses stacked 802.1Q/802.1ad VLAN tags, IPv4, IPv6 extension headers, TCP/UDP ports, and TCP SYN/FIN/RST flags.
- Counts non-IP frames separately. Truncated record data and invalid PCAP headers are reported as errors.
- Does not support pcapng, non-Ethernet capture link types, live capture, DNS/TLS application decoding, packet reassembly, or payload signatures.

Only analyze captures you are authorized to handle. PCAP files can contain sensitive addresses and traffic metadata; keep the input and generated CSV in an appropriate location.
