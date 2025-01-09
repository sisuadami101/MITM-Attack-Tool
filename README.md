# MITM Tool 
**[ Man-in-the-Middle Attack Tool ]**

This tool is a **Man-in-the-Middle (MITM) attack** script written in Python. It allows you to intercept network traffic between a target and gateway, capture sensitive HTTP data, and send it to your email. It supports ARP spoofing and packet sniffing, making it suitable for ethical hacking, penetration testing, and security research.

## Features:
- ARP Spoofing to intercept traffic.
- Packet sniffing to capture HTTP data.
- Email notifications with captured data.
- Auto-remove feature after 30 minutes to clean up the script.

## Requirements:
- Python 3.x
- Scapy library (`pip install scapy`)
- Active Gmail account (for sending captured data)
- Root or administrative privileges on the system

## Installation:
1. Ensure Python 3.x is installed on your system.
2. Install the required dependencies by running:
3. Save the `mitm_tool.py` script to your local machine.

## Installation Instructions

### Step 1: Install Termux
Download and install **Termux** from the Google Play Store or [official GitHub](https://github.com/termux/termux-app).

### Step 2: Install Python and Dependencies
In Termux, execute the following commands to install dependencies:

```bash
pkg update
pkg install termux-api
pkg install python
pkg install git
pkg install openssl
pkg install curl
pip install scapy
```


## Usage:

1. **Clone/Download the repository** and navigate to the script folder.
2. **Run the script** with Python:

3. **Input Required Information**:
- **Sender Gmail address**: Enter your Gmail address (used to send captured data).
- **Sender Gmail password**: Enter the password for the sender Gmail account.
- **Receiver email address**: Enter the email address where you want the captured data to be sent.
- **Target IP**: Enter the IP address of the target you want to intercept.
- **Gateway IP**: Enter the gateway IP address (usually the router's IP).
- **Network Interface**: Enter the network interface you're using (e.g., `wlan0` for wireless).

4. **How it works**:
- The script starts the MITM attack by spoofing ARP requests between the target and the gateway.
- It captures HTTP data such as URLs and POST request data from the target.
- The captured data is then sent via email to the specified email address.

5. **Auto-removal**: After 30 minutes, the script will automatically delete itself from the system and exit.
6. **Interrupt the attack** by pressing `CTRL + C`. The ARP tables will be restored, and IP forwarding will be disabled.

## Important Notes:
- This tool should only be used for educational purposes, ethical hacking, and penetration testing within authorized environments.
- Using this tool for malicious purposes is illegal and unethical. Always obtain written permission before performing penetration testing or network attacks.

## License:
MIT License. See `LICENSE` for more details.

## Author:
Created by **ErrorMask**

## Disclaimer:

**Ethical Use Only:** This tool should only be used for educational purposes, ethical hacking, and authorized penetration testing.
**Unauthorized Access is Illegal:** Unauthorized access to computer systems, networks, or data is prohibited and may lead to criminal prosecution.
**Obtain Permission:** Always obtain written permission from the system owner or network administrator before conducting any penetration testing or MITM attack.
**No Malicious Use:** This script is not intended for malicious or harmful purposes. The author is not responsible for any illegal activities resulting from misuse.
**Legal Compliance:** Ensure compliance with local and international cyber laws when using this tool.
**Security Research:** Use this tool only in controlled environments where you have explicit permission to test network security.

This tool is intended for **educational purposes** and **ethical hacking** only. Unauthorized access or malicious use is **illegal** and **punishable** under **cyber laws**. Always get **proper authorization** before performing any penetration testing or network attacks.
## The author is not responsible for any illegal activity resulting from the misuse of this script.
