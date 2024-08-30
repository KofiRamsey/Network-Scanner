#!/usr/bin/env python3

from scapy.all import ARP, Ether, srp
import ipaddress
import sys

def scan_network(target_ip):
    # Create an ARP request packet
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    # Send the packet and capture the response
    result = srp(packet, timeout=3, verbose=False)[0]

    # List to store discovered devices
    devices = []

    # Process the results
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def print_devices(devices):
    print(f"{'IP Address':<15} {'MAC Address':<17}")
    print('-' * 32)
    for device in devices:
        print(f"{device['ip']:<15} {device['mac']:<17}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python network_scan.py <network>")
        sys.exit(1)

    network = sys.argv[1]

    # Validate and format the network address
    try:
        ip_network = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        print(f"Invalid network address: {e}")
        sys.exit(1)

    # Scan the network
    target_ip = str(ip_network.network_address) + "/24"
    devices = scan_network(target_ip)

    # Print the results
    print_devices(devices)
