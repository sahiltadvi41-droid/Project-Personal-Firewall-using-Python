# Project-Personal-Firewall-using-Python
# Introduction
In the modern digital landscape, the rise in cyber threats makes personal security tools increasingly essential. This project aims to develop a lightweight personal firewall using Python. It is capable of sniffing, filtering, and logging network traffic based on customizable rules. This firewall is ideal for learning network security concepts and creating a foundational security tool.
# Abstract
This project demonstrates the creation of a personal firewall that captures and filters network traffic in real-time using Python and the Scapy library. The firewall applies user-defined rules to allow or block packets based on IP addresses, ports, and protocols. Logged data provides visibility into allowed and blocked communications, while optional integrations with Linux iptables and a Tkinter GUI add enforcement and interactivity.
# Tools Used
- Python 3
- Scapy (pip install scapy)
- Linux iptables (for enforcing rules)
- Tkinter (for optional GUI interface)
- Text editor (e.g., VS Code, nano)
# Features
- Real-time packet sniffing using Scapy
- Rule-based filtering for IP, port, protocol
- Activity logging with timestamps
- Optional iptables integration for system-level enforcement
- Optional Tkinter-based GUI for live monitoring

# How to Run
### 1. Install Requirements
````
   pip install scapy
````
### 2. Run the Script
````
sudo python3 firewall.py

firewall.py:- 
from scapy.all import sniff, IP, TCP, UDP
import datetime

# Define rule sets
allowed_ips = ['192.168.1.1']
blocked_ports = [23, 445]
allowed_protocols = ['TCP', 'UDP']
log_file = "firewall_log.txt"

# Log packets to file
def log_packet(packet, reason):
    with open(log_file, "a") as f:
        f.write(f"{datetime.datetime.now()} - {reason}: {packet.summary()}\n")

# Rule engine
def rule_engine(packet):
    if IP in packet:
        src_ip = packet[IP].src
        proto = packet[IP].proto

        if TCP in packet or UDP in packet:
            port = packet[TCP].dport if TCP in packet else packet[UDP].dport
            if src_ip not in allowed_ips:
                print(f"[!] Blocked IP: {src_ip}")
                return False
            if port in blocked_ports:
                print(f"[!] Blocked Port: {port}")
                return False
    return True

# Callback
def packet_callback(packet):
    if not rule_engine(packet):
        log_packet(packet, "Blocked")
    else:
        log_packet(packet, "Allowed")

# Start sniffing
print("[*] Starting Firewall...")
sniff(prn=packet_callback, store=False)
````

<img width="1916" height="930" alt="image" src="https://github.com/user-attachments/assets/3ad95539-0e8f-439f-b53d-71d56422f072" />
