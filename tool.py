import os
import socket
import ssl
import requests
import threading
from colorama import Fore, Style
from datetime import datetime
import subprocess
import platform
import scapy.all as scapy

def banner():
    os.system('cls' if os.name == 'nt' else 'clear')
    print(Fore.GREEN + r"""
     █████╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
    ██╔══██╗██╔══██╗██║ ██╔╝██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    ███████║██████╔╝█████╔╝ ██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ██╔══██║██╔═══╝ ██╔═██╗ ██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
    ██║  ██║██║     ██║  ██╗╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
    ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
    
    Coded by @MrRobot | Inspired by fsociety | Mr. Robot vibes
    """ + Style.RESET_ALL)

def menu():
    print(Fore.CYAN + """
[01] -> Scan IP Info
[02] -> Whois Lookup
[03] -> Ping Target (Basic)
[04] -> Port Scan
[05] -> TCP Scan (common ports)
[06] -> UDP Scan (common ports)
[07] -> SSL Certificate Info
[08] -> Service Info (Port Services)
[09] -> ARP Scan (Local Network)
[00] -> Exit
""" + Style.RESET_ALL)

def ip_info():
    ip = input("Enter IP address or domain: ")
    url = f"http://ip-api.com/json/{ip}"
    try:
        r = requests.get(url).json()
        for k, v in r.items():
            print(f"{k}: {v}")
    except:
        print("Failed to get IP info.")

def whois_lookup():
    domain = input("Enter domain: ")
    try:
        r = requests.get(f"https://api.hackertarget.com/whois/?q={domain}")
        print(r.text)
    except:
        print("Failed to fetch whois info.")

def ping_target():
    target = input("Enter IP or domain: ")
    os.system(f"ping -c 4 {target}" if os.name != 'nt' else f"ping {target}")

def port_scan():
    target = input("Enter target IP or domain: ")
    try:
        start_port = int(input("Start port: "))
        end_port = int(input("End port: "))
        print(f"\nScanning {target} from port {start_port} to {end_port}...\n")
        for port in range(start_port, end_port + 1):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((target, port))
            if result == 0:
                print(Fore.GREEN + f"[+] Port {port} is OPEN" + Style.RESET_ALL)
            s.close()
    except:
        print(Fore.RED + "[!] An error occurred during port scanning." + Style.RESET_ALL)

def tcp_scan():
    target = input("Enter target IP or domain: ")
    ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 8080]
    print(f"\n[+] Scanning TCP ports on {target}...\n")
    
    def scan(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        result = s.connect_ex((target, port))
        if result == 0:
            print(Fore.GREEN + f"[TCP] Port {port} is OPEN" + Style.RESET_ALL)
        s.close()

    for port in ports:
        thread = threading.Thread(target=scan, args=(port,))
        thread.start()

def udp_scan():
    target = input("Enter target IP or domain: ")
    ports = [53, 67, 68, 69, 123, 161, 162, 500]
    print(f"\n[+] Scanning UDP ports on {target}...\n")

    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1)
            sock.sendto(b'', (target, port))
            data, _ = sock.recvfrom(1024)
            print(Fore.GREEN + f"[UDP] Port {port} is OPEN or FILTERED" + Style.RESET_ALL)
        except socket.timeout:
            print(Fore.YELLOW + f"[UDP] Port {port} is FILTERED (no response)" + Style.RESET_ALL)
        except:
            print(Fore.RED + f"[UDP] Port {port} is CLOSED or unreachable" + Style.RESET_ALL)
        finally:
            sock.close()

def ssl_certificate_info():
    domain = input("Enter domain for SSL certificate info: ")
    port = 443  # Default SSL port

    try:
        # Establish a socket connection to the domain on port 443 (HTTPS)
        context = ssl.create_default_context()
        connection = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain)
        connection.connect((domain, port))

        # Get the certificate in PEM format
        cert = connection.getpeercert()

        # Display certificate details
        print(f"\n[+] SSL Certificate Info for {domain}:")
        print(f"Issuer: {cert['issuer']}")
        print(f"Subject: {cert['subject']}")
        print(f"Serial Number: {cert['serialNumber']}")
        print(f"Not Before: {cert['notBefore']}")
        print(f"Not After: {cert['notAfter']}")

        # Convert date formats
        not_before = datetime.strptime(cert['notBefore'], "%b %d %H:%M:%S %Y GMT")
        not_after = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y GMT")
        print(f"Validity Period: {not_before.strftime('%Y-%m-%d')} to {not_after.strftime('%Y-%m-%d')}")

        connection.close()
    except Exception as e:
        print(Fore.RED + f"[!] Failed to get SSL certificate for {domain}: {e}" + Style.RESET_ALL)

def service_info():
    target = input("Enter target IP or domain: ")
    known_services = {
        21: 'FTP',
        22: 'SSH',
        23: 'Telnet',
        25: 'SMTP',
        53: 'DNS',
        80: 'HTTP',
        443: 'HTTPS',
        3306: 'MySQL',
        8080: 'HTTP-Alternate'
    }
    try:
        start_port = int(input("Start port: "))
        end_port = int(input("End port: "))
        print(f"\n[+] Scanning ports on {target}...\n")
        for port in range(start_port, end_port + 1):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            result = s.connect_ex((target, port))
            if result == 0:
                service = known_services.get(port, 'Unknown Service')
                print(Fore.GREEN + f"[+] Port {port} is OPEN - Service: {service}" + Style.RESET_ALL)
            s.close()
    except:
        print(Fore.RED + "[!] An error occurred during service scanning." + Style.RESET_ALL)

def arp_scan():
    target_ip = input("Enter the IP range (e.g., 192.168.1.0/24): ")

    print("[+] Scanning for devices in the local network...")
    arp_request = scapy.ARP(pdst=target_ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    print(f"\n[+] Devices in the network {target_ip}:")
    for element in answered_list:
        print(f"IP Address: {element[1].psrc} - MAC Address: {element[1].hwsrc}")

# Ana Menü Döngüsü
while True:
    banner()
    menu()
    choice = input(">> ")

    if choice in ["1", "01"]:
        ip_info()
    elif choice in ["2", "02"]:
        whois_lookup()
    elif choice in ["3", "03"]:
        ping_target()
    elif choice in ["4", "04"]:
        port_scan()
    elif choice in ["5", "05"]:
        tcp_scan()
    elif choice in ["6", "06"]:
        udp_scan()
    elif choice in ["7", "07"]:
        ssl_certificate_info()
    elif choice in ["8", "08"]:
        service_info()
    elif choice in ["9", "09"]:
        arp_scan()
    elif choice in ["0", "00"]:
        print("Goodbye.")
        break
    else:
        print("Invalid choice.")
    input("\nPress Enter to return to menu...")
