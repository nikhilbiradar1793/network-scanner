import socket
import threading
import csv
from scapy.all import ARP, Ether, srp

# Common ports with service names
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    139: "NetBIOS",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP"
}

scan_results = {}


# ---------------- Device Discovery (ARP Scan) ----------------
def discover_devices(network):
    print("\n[*] Scanning for active devices...\n")

    arp = ARP(pdst=network)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=2, verbose=False)[0]

    devices = []

    for sent, received in result:
        print(f"[+] Device Found: IP={received.psrc}, MAC={received.hwsrc}")
        devices.append(received.psrc)

    return devices


# ---------------- Port Scanning ----------------
def scan_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((ip, port))
        if result == 0:
            banner = grab_banner(sock)
            service = COMMON_PORTS.get(port, "Unknown")

            print(f"[OPEN] {ip}:{port} ({service})")
            scan_results[ip].append((port, service, banner))

        sock.close()
    except:
        pass


def grab_banner(sock):
    try:
        sock.send(b"Hello\r\n")
        return sock.recv(1024).decode().strip()
    except:
        return "No banner"


def scan_ports(ip):
    scan_results[ip] = []
    threads = []

    for port in COMMON_PORTS.keys():
        t = threading.Thread(target=scan_port, args=(ip, port))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()


# ---------------- Save Results ----------------
def save_to_csv():
    with open("scan_results.csv", "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["IP Address", "Port", "Service", "Banner"])

        for ip, data in scan_results.items():
            for port, service, banner in data:
                writer.writerow([ip, port, service, banner])

    print("\n[*] Results saved to scan_results.csv")


# ---------------- Main ----------------
def main():
    print("=== Automated Network Scanner ===")
    print("⚠ Scan only authorized networks\n")

    network = input("Enter network (Example: 192.168.1.1/24): ")

    devices = discover_devices(network)

    print("\n[*] Scanning open ports...\n")

    for device in devices:
        scan_ports(device)

    save_to_csv()

    print("\n=== Scan Complete ===")


if __name__ == "__main__":
    main()
