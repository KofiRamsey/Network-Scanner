# Network Scanner

This Python script performs a simple network scan to discover devices on a specified network. It sends ARP requests and listens for responses to identify active devices, displaying their IP and MAC addresses.

## Features

- **ARP Request**: The script generates ARP requests to the specified network, seeking out active devices.
- **Ethernet Frame**: Uses Ethernet frames to send broadcast requests to all devices in the target network.
- **Device Discovery**: Captures responses and identifies devices by their IP and MAC addresses.
- **Simple Output**: Displays a list of all discovered devices.

## Requirements

- Python 3.x
- Scapy library (`scapy`)

## Installation

1. **Install Python 3**: Ensure that Python 3 is installed on your system. You can download it from the [official Python website](https://www.python.org/downloads/).
   
2. **Install Scapy**: Install the Scapy library using `pip`:
   ```bash
   pip install scapy
   ```

## Usage

To use the network scanner, run the script with the network address as an argument:

```bash
python network_scan.py <network>
```

### Example

```bash
python network_scan.py 192.168.1.0/24
```

This command scans the `192.168.1.0/24` network and lists all devices that respond to the ARP request.

### Output

The script outputs a table with the following columns:

- **IP Address**: The IP address of the discovered device.
- **MAC Address**: The MAC address of the discovered device.

Example output:

```
IP Address      MAC Address      
--------------------------------
192.168.1.1     00:11:22:33:44:55
192.168.1.2     66:77:88:99:AA:BB
...
```

## Error Handling

- **Invalid Network Address**: If the network address provided is invalid, the script will terminate with an error message.
  
```bash
Invalid network address: <error_message>
```

- **Incorrect Usage**: If the script is run without the correct number of arguments, it will display the usage instructions.

```bash
Usage: python network_scan.py <network>
```

## Notes

- **Network Range**: The script assumes a `/24` network range by default. Ensure that the network address provided is within a valid range.
- **Root Privileges**: Depending on your operating system, you might need to run this script with root or administrative privileges to send ARP requests.

## Disclaimer

This script is intended for educational purposes and network troubleshooting on networks you own or have explicit permission to scan. Unauthorized scanning of networks may be illegal in some jurisdictions. Always ensure you have permission before scanning any network.
