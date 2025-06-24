from scapy.all import IP, ICMP, sr1
from concurrent.futures import ThreadPoolExecutor
from termcolor import colored
from colorama import init
from ipaddress import ip_network
from utils import handle_scan_output,resolve_hostname
import time

init()

class Output:
    @staticmethod
    def print_icmp_banner():
        print("\n" + "-"*60)
        print(colored("[+] Starting ICMP host discovery scan", "cyan"))
        print("-"*60)
        print(f"{'Hostname':<20}{'Host':<20}{'Status':<10}")
        print("-"*60)
    
    @staticmethod
    def print_tracert_banner():
        print("\n" + "-" * 60)
        print(colored("[+] Starting Trace Routing with ICMP echo probes.", "cyan"))
        print("-" * 60)
        print(f"{'Hop':<5}{'IP':<20}{'Latency':<15}")
        print("-" * 60)

    @staticmethod
    def print_icmp_result(hostname, ip, status):
        status_colors = {
            "ACTIVE": "green",
            "INACTIVE": "red"
        }
        print(f"{hostname:<20}{ip:<20}{colored(status, status_colors.get(status, 'white'))}")
        
    @staticmethod
    def print_icmp_tracert_result(ttl, ip, rtt):
        ip_display = ip if ip else "*"
        rtt_display = f"{rtt:.2f} ms" if rtt else "Timeout"
        print(f"{ttl:<5}{ip_display:<20}{rtt_display:<15}")

class ICMPScan:
    @staticmethod
    def icmp_scan(target_ip, timeout, retries, filename, ftype, silent, max_workers=50):
        try:
            network = ip_network(target_ip, strict=False)
        except ValueError:
            print(f"[!] Invalid IP or network range: '{target_ip}'")
            return []

        if not silent:
            Output.print_icmp_banner()

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            results = executor.map(lambda ip: ICMPScan.ping_ip(ip, timeout, retries), network.hosts())

        active_ips = []

        for hostname, ip, active in results:
            status = "ACTIVE" if active else "INACTIVE"
            if not silent:
                Output.print_icmp_result(hostname, ip, status)
            active_ips.append({
                "hostname": hostname,
                "ip": ip,
                "status": status
            })

        handle_scan_output(active_ips, scantype="ICMP", filename=filename, ftype=ftype) 

        return active_ips

    @staticmethod
    def ping_ip(ip, timeout, retries):
        try:
            pkt = IP(dst=str(ip)) / ICMP()
            hostname = "Unknown"

            for attempt in range(retries):
                resp = sr1(pkt, timeout=timeout, verbose=0)
                if resp:
                    hostname = resolve_hostname(ip)
                    return (hostname, str(ip), True)
                time.sleep(0.1)
        except Exception:
            pass
        return (hostname, str(ip), False)
    
class ICMPtracert:
    @staticmethod
    def icmp_trace(target_ip, timeout, retries, filename, ftype, silent, max_hops=30):
        if not silent:
            Output.print_tracert_banner()

        hops = []
        for ttl in range(1, max_hops + 1):
            ip = None
            rtt = None
            for attempt in range(retries):
                pkt = IP(dst=target_ip, ttl=ttl) / ICMP()
                start = time.time()
                resp = sr1(pkt, timeout=timeout, verbose=0)
                rtt = (time.time() - start) * 1000

                if resp:
                    ip = resp.src
                    break

            if not silent:
                Output.print_icmp_tracert_result(ttl, ip, rtt)

            hops.append({
                "hop": ttl,
                "ip": ip if ip else "*",
                "rtt": round(rtt, 2) if rtt else None
            })

            if resp and resp.type == 0:
                break
            
            handle_scan_output(hops, scantype="traceroute", filename=filename, ftype=ftype)

        return hops