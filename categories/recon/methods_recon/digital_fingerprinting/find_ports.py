import socket
import random
from scapy.all import IP, TCP, ICMP, send, sr1
import argparse
import sys
import time
from concurrent.futures import ThreadPoolExecutor
import ipaddress
from termcolor import colored
from itertools import product


COMMON_PORTS = {
    20: "FTP (Data)",
    21: "FTP (Control)",
    22: "SSH / SFTP",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP (Server)",
    68: "DHCP (Client)",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind / portmapper",
    119: "NNTP",
    123: "NTP",
    135: "Microsoft RPC",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    179: "BGP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB / CIFS",
    465: "SMTPS (legacy)",
    514: "Syslog",
    515: "LPD (Printer)",
    520: "RIP",
    587: "SMTP (Submission)",
    631: "IPP (Printing)",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1433: "MSSQL",
    1434: "MSSQL Monitor",
    1521: "Oracle DB",
    1701: "L2TP",
    1812: "RADIUS (Auth)",
    1813: "RADIUS (Acct)",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel (SSL)",
    2100: "Oracle XDB",
    2483: "Oracle DB (TCP)",
    2484: "Oracle DB (SSL)",
    3306: "MySQL",
    3389: "RDP (Remote Desktop)",
    3690: "Subversion",
    4000: "ICQ",
    4444: "Metasploit / Oracle",
    5000: "UPnP / Flask Dev",
    5060: "SIP (VoIP)",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)",
    6379: "Redis",
    6667: "IRC",
    8000: "HTTP Alt / Dev",
    8080: "HTTP Proxy / Alt",
    8443: "HTTPS Alt / Admin UI",
    8888: "Web UI / Proxy",
    9000: "PHP-FPM / Dev Tools",
    9200: "Elasticsearch",
    9300: "Elasticsearch Node",
    11211: "Memcached",
    27017: "MongoDB",
    50000: "SAP / Sybase / IBM DB2",
}


class Utilities:

    @staticmethod
    def randomize_sport():
        return random.randint(49152, 65535)
    
    @staticmethod
    def random_port(start=1024, end=65535):
        return random.randint(start, end)

    @staticmethod
    def randomize_seq():
        return random.getrandbits(32)

    @staticmethod
    def randomize_window():
        return random.choice([5840, 8192, 16384, 65535, 14600, 32120, 29200])

    @staticmethod
    def randomize_ttl():
        return random.choice([64, 128, 255])

    @staticmethod
    def randomize_time(scan_method):
        if scan_method == "stealth":
            return random.uniform(0.3, 1.5)
        elif scan_method == "connect":
            return random.uniform(0.05, 0.2)
        elif scan_method in ["FIN", "XMAS", "ACK"]:
            return random.uniform(0.2, 0.5)
        return 0.1
    
class PortScan:
        
    @staticmethod
    def parse_tcp_flags(extra_args):
        parser = argparse.ArgumentParser()
        parser.add_argument('--stealth', '-s', action='store_true', help='Perform stealth (SYN) scan')
        parser.add_argument('--port', '-p', type=str, default=None, help='Comma-separated list of ports (e.g., 80,443)')
        parser.add_argument('--fin', '-f', action='store_true', help='Perform FIN scan')
        parser.add_argument('--ack', '-a', action='store_true', help='Perform ACK scan')
        parser.add_argument('--xmas', '-x', action='store_true', help='Perform XMAS scan')
        parser.add_argument('--aggressive', '-A', action='store_true', help='Perform Aggressive scan')
        args, unknown = parser.parse_known_args(extra_args)
        if unknown:
            print(f"[!] Warning: Unknown TCP scan options ignored: {unknown}")

        if args.port:
            try:
                ports = [int(p.strip()) for p in args.port.split(',')]
                for port in ports:
                    if port < 1 or port > 65535:
                        raise ValueError(f"Port {port} out of valid range 1-65535")
                args.port = ports
            except ValueError as e:
                print(f"[!] Invalid port list: {e}")
                sys.exit(1)
        else:
            args.port = None

        return args

    @staticmethod
    def Scan_method_handler(ip_range, tcp_flags=None, timeout=1, retries=1, max_workers=200):
        try:
            network = ipaddress.ip_network(ip_range, strict=False)
        except ValueError:
            print(colored(f"[!] Invalid IP range: {ip_range}", "red"))
            return []

        ports = tcp_flags.port if tcp_flags and tcp_flags.port else list(COMMON_PORTS.keys())

        if tcp_flags:
            if tcp_flags.aggressive:
                scan_funcs = [SCAN_METHODS["stealth"], SCAN_METHODS["ACK"], SCAN_METHODS["FIN"]]
            elif tcp_flags.stealth:
                scan_funcs = [SCAN_METHODS["stealth"]]
            elif tcp_flags.fin:
                scan_funcs = [SCAN_METHODS["FIN"]]
            elif tcp_flags.xmas:
                scan_funcs = [SCAN_METHODS["XMAS"]]
            elif tcp_flags.ack:
                scan_funcs = [SCAN_METHODS["ACK"]]
            else:
                scan_funcs = [SCAN_METHODS["connect"]]
        else:
            scan_funcs = [SCAN_METHODS["connect"]]

        all_results = {}
        scanned_pairs = set()

        for scan_func in scan_funcs:
            scan_name = scan_func.__name__

            targets = [
                (ip, port) for ip, port in product(network.hosts(), ports)
                if (str(ip), port) not in scanned_pairs
            ]

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                results = list(executor.map(lambda ip_port: scan_func(ip_port[0], [ip_port[1]], timeout, retries), targets))

            for ip, port_list in results:
                for port in port_list:
                    scanned_pairs.add((ip, port))

            formatted_results = {}
            for ip, port_list in results:
                if ip not in formatted_results:
                    formatted_results[ip] = set()
                formatted_results[ip].update(port_list)

            final_results = []
            for ip, port_set in formatted_results.items():
                open_ports = []
                filtered_ports = []
                services = []

                if scan_name in ['ACK', 'stealth', 'FIN']:
                    filtered_ports = sorted(port_set)
                else:
                    open_ports = sorted(port_set)
                    for port in open_ports:
                        banner = PortScan.grab_banner(ip, port, timeout)
                        services.append({
                            "port": port,
                            "banner": banner or COMMON_PORTS.get(port, "Unknown")
                        })

                final_results.append({
                    "ip": ip,
                    "open_ports": open_ports,
                    "filtered_ports": filtered_ports,
                    "services": services,
                    "scan_type": scan_name
                })

            all_results[scan_name] = final_results

        return all_results


    @staticmethod
    def grab_banner(ip, port, timeout=2):
        try:
            with socket.create_connection((ip, port), timeout=timeout) as s:
                s.settimeout(timeout)
                return s.recv(1024).decode(errors="ignore").strip()
        except Exception:
            return None

    #note : might not be used but keeping it in case of scalability
    @staticmethod
    def imcp_probe(ips, timeout, retries):
        responsive_ips = []
        for ip in ips:
            pkt = IP(dst=str(ip)) / ICMP()
            for _ in range(retries):
                try:
                    resp = sr1(pkt, timeout=timeout, verbose=0)
                    if resp:
                        responsive_ips.append(ip)
                        break
                except Exception:
                    pass
                time.sleep(0.1)
        return responsive_ips
     
    @staticmethod
    def connect_scan(ip, ports, timeout, retries):
        open_ports = []
        for port in ports:
            try:
                for _ in range(retries):
                    src_port = Utilities.randomize_sport()
                    seq_num = Utilities.randomize_seq()
                    window_size = Utilities.randomize_window()
                    ttl_value = Utilities.randomize_ttl()

                    syn_packet = IP(dst=str(ip), ttl=ttl_value) / TCP(
                        sport=src_port,
                        dport=port,
                        flags="S",
                        seq=seq_num,
                        window=window_size
                    )
                    syn_ack_response = sr1(syn_packet, timeout=timeout, verbose=0)

                    if syn_ack_response and syn_ack_response.haslayer(TCP):
                        tcp_layer = syn_ack_response.getlayer(TCP)
                        if tcp_layer.flags & 0x12 == 0x12:
                            ack_packet = IP(dst=str(ip), ttl=ttl_value) / TCP(
                                sport=src_port,
                                dport=port,
                                flags="R",
                                seq=seq_num + 1,
                                ack=tcp_layer.seq + 1,
                                window=window_size
                            )
                            send(ack_packet, verbose=0)
                            open_ports.append(port)
                            break

                    time.sleep(0.01)
            except Exception as e:
                print(f"[!] Error scanning {ip}:{port} - {e}")
        return (str(ip), open_ports)

    @staticmethod
    def stealth_scan(ip, ports, timeout, retries):
        open_ports = []
        for port in ports:
            try:
                for _ in range(retries):
                    src_port = Utilities.randomize_sport()
                    seq_num = Utilities.randomize_seq()
                    window_size = Utilities.randomize_window()
                    ttl_value = Utilities.randomize_ttl()

                    syn_packet = IP(dst=str(ip), ttl=ttl_value) / TCP(sport=src_port, dport=port, flags='S', seq=seq_num, window=window_size)
                    syn_ack_resp = sr1(syn_packet, timeout=timeout, verbose=0)

                    if syn_ack_resp and syn_ack_resp.haslayer(TCP):
                        tcp_layer = syn_ack_resp.getlayer(TCP)
                        if tcp_layer.flags & 0x12 == 0x12:
                            rst_packet = IP(dst=str(ip), ttl=ttl_value) / TCP(sport=src_port, dport=port, flags='R', seq=seq_num + 1, window=window_size)
                            send(rst_packet, verbose=0)
                            open_ports.append(port)
                            break
                    time.sleep(0.01)
            except Exception as e:
                print(f"[!] Error scanning {ip}:{port} - {e}")
        return (str(ip), open_ports)

    @staticmethod
    def XMAS_scan(ip, ports, timeout, retries):
        open_ports = []

        for port in ports:
            try:
                for _ in range(retries):
                    src_port = Utilities.randomize_sport()
                    seq_num = Utilities.randomize_seq()
                    window_size = Utilities.randomize_window()
                    ttl_value = Utilities.randomize_ttl()

                    xmas_packet = IP(dst=str(ip), ttl=ttl_value) / TCP(
                        sport=src_port,
                        dport=port,
                        flags="FUP",
                        seq=seq_num,
                        window=window_size
                    )
                    response = sr1(xmas_packet, timeout=timeout, verbose=0)

                    if response is None:
                        open_ports.append(port)
                        break

                    if response.haslayer(TCP) and response[TCP].flags == 0x14:
                        break

                    time.sleep(0.01)
            except Exception as e:
                print(f"[!] Error scanning {ip}:{port} - {e}")

        return (str(ip), open_ports)

    @staticmethod
    def FIN_scan(ip, ports, timeout, retries):
        open_ports = []

        for port in ports:
            try:
                for _ in range(retries):
                    src_port = Utilities.randomize_sport()
                    seq_num = Utilities.randomize_seq()
                    window_size = Utilities.randomize_window()
                    ttl_value = Utilities.randomize_ttl()

                    fin_packet = IP(dst=str(ip), ttl=ttl_value) / TCP(
                        sport=src_port,
                        dport=port,
                        flags="F",
                        seq=seq_num,
                        window=window_size
                    )
                    response = sr1(fin_packet, timeout=timeout, verbose=0)

                    if response is None:
                        open_ports.append(port)
                        break

                    if response.haslayer(TCP) and response[TCP].flags == 0x14:
                        break

                    time.sleep(0.01)
            except Exception as e:
                print(f"[!] Error scanning {ip}:{port} - {e}")

        return (str(ip), open_ports)

    @staticmethod
    def ACK_scan(ip, ports, timeout, retries):
        filtered_ports = []

        for port in ports:
            try:
                for _ in range(retries):
                    src_port = Utilities.randomize_sport()
                    seq_num = Utilities.randomize_seq()
                    window_size = Utilities.randomize_window()
                    ttl_value = Utilities.randomize_ttl()

                    ack_packet = IP(dst=str(ip), ttl=ttl_value) / TCP(
                        sport=src_port, dport=port, flags="A", seq=seq_num, window=window_size
                    )
                    response = sr1(ack_packet, timeout=timeout, verbose=0)

                    if response is None:
                        filtered_ports.append(port)
                        break

                    elif response.haslayer(ICMP):
                        icmp = response.getlayer(ICMP)
                        if icmp.type == 3 and icmp.code in [1, 2, 3, 9, 10, 13]:
                            filtered_ports.append(port)
                            break

                    elif response.haslayer(TCP) and response.getlayer(TCP).flags == 0x04:
                        break
                    
            except Exception as e:
                print(f"[!] Error scanning {ip}:{port} - {e}")

        return (str(ip), filtered_ports)


SCAN_METHODS = {
    "connect": PortScan.connect_scan,
    "stealth": PortScan.stealth_scan,
    "FIN": PortScan.FIN_scan,
    "ACK": PortScan.ACK_scan,
    "XMAS": PortScan.XMAS_scan,
}