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
<img width="1919" height="937" alt="image" src="https://github.com/user-attachments/assets/f2cd0a2b-0431-43dd-b524-d8872b6b7542" />

### 3. Customize Rules
 Edit the following variables in firewall.py to define custom filtering rules:
 ````
allowed_ips = ['192.168.1.1']
blocked_ports = [23, 445]
allowed_protocols = ['TCP', 'UDP']
````
## Output
- All blocked and allowed packets are logged in firewall_log.txt with timestamps and reasons.
- Example:
````
2025-07-23 13:45:02.123456 - Blocked: IP / TCP 192.168.1.100:445 > 192.168.1.2
````

## Optional: GUI Monitoring
You can build a GUI using Tkinter to display packets in real-time. It will allow you to visualize traffic and alerts as they happen.
````
import tkinter as tk

def update_display(text):
    text_area.insert(tk.END, text + "\n")
    text_area.see(tk.END)

window = tk.Tk()
window.title("Firewall Monitor")
text_area = tk.Text(window, height=20, width=80)
text_area.pack()

def gui_packet_callback(packet):
    summary = packet.summary()
    update_display(summary)
    if not rule_engine(packet):
        log_packet(packet, "Blocked")

sniff(prn=gui_packet_callback, store=False)
window.mainloop()

---

##  Optional: Enforcing with iptables
To drop packets from blocked IPs using system-level firewall:
```bash
sudo iptables -A INPUT -s 192.168.1.100 -j DROP
````

## Optional: Enforce Rules with iptables
````
sudo iptables -A INPUT -s 192.168.1.100 -j DROP
````
In Python:
````
import os
os.system("sudo iptables -A INPUT -s 192.168.1.100 -j DROP")
````

## Conclusion
This project provides hands-on experience in building a personal firewall using Python. By leveraging Scapy for packet sniffing and rule enforcement, users learn about network protocols, real-time monitoring, and packet-level filtering. It can be expanded with anomaly detection, machine learning, or deeper OS-level integrations for advanced use cases.

