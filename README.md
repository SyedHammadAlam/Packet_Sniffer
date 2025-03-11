# Packet Sniffer with Security Monitoring

## Overview
This advanced packet sniffer monitors network traffic in real-time, logs packets, and detects access to suspicious websites. It analyzes DNS queries and extracts URLs to identify potential threats. If a match is found in the predefined list of suspicious websites, the program triggers an alert to warn the user, ensuring enhanced security monitoring.

## Features
- **Real-time Packet Capture**: Monitors and logs network packets dynamically.
- **IP & Protocol Analysis**: Extracts source and destination IP addresses along with protocol details.
- **DNS Query Monitoring**: Identifies domain names from DNS requests.
- **URL Extraction**: Detects URLs from raw packet payloads (HTTP, UDP traffic).
- **Suspicious Website Detection**: Compares extracted domains/URLs against a predefined blacklist.
- **Security Alerts**: Displays a pop-up warning if a suspicious website is accessed.
- **Log Management**: Saves all captured data in `packet_logs.txt` for further analysis.

## Prerequisites
Ensure you have the following installed before running the script:
- **Python 3.x**
- **Required Python libraries:**
  - `scapy`
  - `tkinter`
  - `re`
  - `socket`

To install `scapy`, run:
```sh
pip install scapy
```

## Usage
1. Clone this repository:
   ```sh
   git clone https://github.com/SyedHammadAlam/packet-sniffer.git
   cd packet-sniffer
   ```
2. Run the script with administrator privileges (required for packet sniffing):
   ```sh
   sudo python Packet_Sniffer.py  # Linux/Mac
   python Packet_Sniffer.py        # Windows (Run as Administrator)
   ```
3. The program will start monitoring network packets.
4. If a suspicious website is accessed, an alert window will appear.
5. All logs will be saved in `packet_logs.txt`.

## How It Works
- Uses **`scapy`** to capture packets from the network interface.
- Extracts **IP addresses, protocol details, and DNS queries**.
- Checks **domain names and URLs** against a list of suspicious websites.
- **Triggers alerts** if any match is found.
- Logs all activity for future security analysis.

## Code Structure
- **`extract_domain(payload)`** → Extracts URLs from packet payloads.
- **`show_alert(message)`** → Displays a security alert pop-up.
- **`log_packet(data)`** → Saves logs to `packet_logs.txt`.
- **`packet_callback(packet)`** → Processes network packets, extracts data, and checks for suspicious domains.
- **`sniff(prn=packet_callback, store=False, iface=conf.iface)`** → Captures packets using the default network interface.

## Limitations
- Requires **administrator/root privileges** to capture network traffic.
- **Limited to local machine traffic** and does not monitor external devices.
- Uses a **predefined list of suspicious websites**, which requires updates for evolving threats.

## Disclaimer
This tool is developed for **educational and security research purposes only**. Unauthorized packet sniffing may violate privacy laws. Use responsibly and ensure compliance with legal frameworks.

## License
This project is licensed under the **MIT License**.

## Author
Developed by **[Syed Hammad Alam](https://github.com/SyedHammadAlam)**

---
If you find this project useful, feel free to ⭐ star the repository on GitHub!

