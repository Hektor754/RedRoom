import ipaddress
from methods import arp_scan, icmp_scan, tcp_scan

def is_local_network(target_range):
    try:
        network = ipaddress.ip_network(target_range, strict=False)
    except ValueError:
        print(f"[!] Invalid IP or network: {target_range}")
        return False

    return network.network_address.is_private

def auto_hostdiscovery(target_ip, timeout=1.0, retries=1, filename=None, ftype=None, extra_tcp_flags=None):
    results = []
    if is_local_network(target_ip):
        print("[*] Local network detected, using ARP scan...")
        try:
            results = arp_scan(target_ip, timeout, retries, filename, ftype, max_workers=50)
            
            if not any(r['status'] == 'ACTIVE' for r in results):
                print("[!] No active hosts found with ARP, falling back to ICMP scan...")
                results = icmp_scan(target_ip, timeout, retries, filename, ftype)
                
        except Exception as e:
            print(f"[!] ARP scan error: {e}, falling back to ICMP scan...")
            results = icmp_scan(target_ip, timeout, retries, filename, ftype)
    else:
        print("[*] Remote network detected, using ICMP scan...")
        try:
            results = icmp_scan(target_ip, timeout, retries, filename, ftype)
            if not any(r['status'] == 'ACTIVE' for r in results):
                print("[!] No active hosts found with ICMP, trying TCP scan...")
                results = tcp_scan(target_ip, extra_tcp_flags, timeout, retries, filename, ftype)
        except Exception as e:
            print(f"[!] ICMP scan error: {e}, trying TCP scan...")
            results = tcp_scan(target_ip, extra_tcp_flags, timeout, retries, filename, ftype)

    active_hosts = [host for host in results if host["status"] == "ACTIVE"]

    return active_hosts