from scapy.all import *
import re
import socket
import tkinter as tk
from tkinter import messagebox

# Hardcode some suspicious websites for comparing the extracted websites 
suspicious_websites = [
    "malicious.com", "phishing-site.net", "192.168.1.100",
    "evil-site.org", "hackerportal.net", "badwebsite.xyz",
    "trojan-source.com", "fraudulent-page.net", "dangerous-link.com"
]

# This function is used to extract website urls from raw packets payloads.It converts into string and prevent crash like dots.
def extract_domain(payload):
    try:
        payload_str = payload.decode(errors='ignore')
        urls = re.findall(r'(?i)\b(?:https?://|www\.)\S+\b', payload_str)
        return [url.rstrip(".") for url in urls] if urls else None              
    except:
        return None

# tk is tkinter.It alerts the user when suspicious website is accessed.Prevents opening suspicious window and hide main window that's why root withdraw is used
def show_alert(message):
    root = tk.Tk()
    root.withdraw() 
    messagebox.showwarning("Security Alert", message)
    root.destroy()


#Saves all the logs in a text file
def log_packet(data):
    with open("packet_logs.txt", "a") as log_file:
        log_file.write(data + "\n")

#This function extract ip address and domains and alert if suspicious website matches.

def packet_callback(packet):
    if packet.haslayer(IP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        log_data = f"[+] Packet: {ip_src} -> {ip_dst} (Protocol: {protocol})"
        print(log_data)
        log_packet(log_data)
        
        # Check DNS packets for domain names
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            domain = packet[DNSQR].qname.decode('utf-8').rstrip(".") 
            log_domain = f"[*] DNS Query: {domain}"
            print(log_domain)
            log_packet(log_domain)
            
            if domain in suspicious_websites:
                alert_message = f"[ALERT] Suspicious website accessed: {domain}"
                print(alert_message)
                show_alert(alert_message)
                log_packet(alert_message)
        
        # Extract URLs from HTTP and UDP traffic
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            extracted_urls = extract_domain(payload)
            if extracted_urls:
                for url in extracted_urls:
                    log_url = f"[*] Extracted URL: {url}"
                    print(log_url)
                    log_packet(log_url)
                    
                    if url in suspicious_websites:
                        alert_message = f"[ALERT] Suspicious URL detected: {url}"
                        print(alert_message)
                        show_alert(alert_message)
                        log_packet(alert_message)

#It starts the packet sniffer auto-detects the network interface and processes each packet using packet_callback()

if __name__ == "__main__":
    print("Starting packet sniffer with network security monitoring...")
    sniff(prn=packet_callback, store=False, iface=conf.iface) 


# We built a packet sniffer that monitors network traffic, logs packets, and detects suspicious websites by analyzing 
# DNS queries and extracted URLs. If a match is found, it triggers an alert; otherwise, it maintains logs for security monitoring.