
---

# Network Packet Sniffer

A robust network packet sniffer built in Python to monitor and analyze network traffic. This project provides insights into how data flows in a network and helps in understanding and securing network communications.

## Key Concepts

- Network protocols
- Packet capturing and analysis
- Security threats in network traffic

## Features

- Capture and display IP, TCP, and UDP packets
- Print packet details including source and destination addresses and ports
- Real-time packet capturing and analysis

## Libraries Used

- [scapy](https://pypi.org/project/scapy/)
- [socket](https://docs.python.org/3/library/socket.html)

## Prerequisites

Ensure you have Python installed and the required libraries (`scapy`, `socket`) are installed.

You can install the required libraries using pip:

```bash
pip install scapy
```

## Usage

1. **Clone the repository**:

    ```bash
    git clone https://github.com/yourusername/network-packet-sniffer.git
    cd network-packet-sniffer
    ```

2. **Run the script with root privileges**:

    ```bash
    sudo python packet_sniffer.py
    ```

3. **Monitor the console output** to see the captured packets and their details.

## Code Overview

### Import Libraries

```python
from scapy.all import *
import socket
import os
import sys
from datetime import datetime
```

### Packet Callback Function

```python
def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            protocol = "TCP"
            print(f"{datetime.now()} - {protocol} Packet: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")
        
        elif UDP in packet:
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            protocol = "UDP"
            print(f"{datetime.now()} - {protocol} Packet: {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}")
        
        else:
            protocol = "Other"
            print(f"{datetime.now()} - {protocol} Packet: {ip_src} -> {ip_dst}")
```

### Start Sniffing

```python
def start_sniffing(interface):
    print(f"[*] Starting packet capture on {interface}")
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("This script must be run as root.")
        sys.exit(1)
    
    interface = "eth0"  # Change to your network interface
    start_sniffing(interface)
```

