from scapy.all import *
import socket
import os
import sys
from datetime import datetime


def packet_callback(packet):
    # Check if the packet has a layer for IP
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        
        # Check if the packet has a layer for TCP
        if TCP in packet:
            tcp_sport = packet[TCP].sport
            tcp_dport = packet[TCP].dport
            protocol = "TCP"
            print(f"{datetime.now()} - {protocol} Packet: {ip_src}:{tcp_sport} -> {ip_dst}:{tcp_dport}")
        
        # Check if the packet has a layer for UDP
        elif UDP in packet:
            udp_sport = packet[UDP].sport
            udp_dport = packet[UDP].dport
            protocol = "UDP"
            print(f"{datetime.now()} - {protocol} Packet: {ip_src}:{udp_sport} -> {ip_dst}:{udp_dport}")
        
        else:
            protocol = "Other"
            print(f"{datetime.now()} - {protocol} Packet: {ip_src} -> {ip_dst}")


def start_sniffing(interface):
    print(f"[*] Starting packet capture on {interface}")
    sniff(iface=interface, prn=packet_callback, store=0)

if __name__ == "__main__":
    # Ensure the script is running as root
    if os.geteuid() != 0:
        print("This script must be run as root.")
        sys.exit(1)
    
    # Set the network interface to listen on
    interface = "eth0"  # Change to your network interface
    start_sniffing(interface)
