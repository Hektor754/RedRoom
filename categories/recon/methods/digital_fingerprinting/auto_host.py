import ipaddress
from ..protocol_scans.arp_scan import ARPScan
from ..protocol_scans.icmp_scan import ICMPScan
from ..protocol_scans.tcp_scan import Handler
from ..protocol_scans.udp_scan import UDPScan

def is_local_network(target_range):
    try:
        network = ipaddress.ip_network(target_range, strict=False)
    except ValueError:
        print(f"[!] Invalid IP or network: {target_range}")
        return False
    return network.network_address.is_private

def auto_hostdiscovery(target_ip, timeout, retries, filename, ftype, silent, extra_tcp_flags):
    results = []
    if is_local_network(target_ip):
        print("[*] Local network detected, using ARP scan...")
        try:
            results = ARPScan.arp_scan(target_ip, timeout, retries, filename, ftype, silent, max_workers=50)
            
            if not any(r['status'] == 'ACTIVE' for r in results):
                print("[!] No active hosts found with ARP, falling back to ICMP scan...")
                results = ICMPScan.icmp_scan(target_ip, timeout, retries, filename, ftype, silent)

                if not any(r['status'] == 'ACTIVE' for r in results):
                    print("[!] No active hosts found with ICMP, trying UDP scan...")
                    results = UDPScan.udp_scan(target_ip, timeout, retries, filename, ftype, silent)
                
        except Exception as e:
            print(f"[!] ARP scan error: {e}, falling back to ICMP scan...")
            results = ICMPScan.icmp_scan(target_ip, timeout, retries, filename, ftype, silent)
            if not any(r['status'] == 'ACTIVE' for r in results):
                print("[!] No active hosts found with ICMP, trying UDP scan...")
                results = UDPScan.udp_scan(target_ip, timeout, retries, filename, ftype, silent)

    else:
        print("[*] Remote network detected, using ICMP scan...")
        try:
            results = ICMPScan.icmp_scan(target_ip, timeout, retries, filename, ftype, silent)
            if not any(r['status'] == 'ACTIVE' for r in results):
                print("[!] No active hosts found with ICMP, trying TCP scan...")
                results = Handler.tcp_scan(target_ip, extra_tcp_flags, timeout, retries, filename, ftype)
                if not any(r['status'] == 'ACTIVE' for r in results):
                    print("[!] No active hosts found with TCP, trying UDP scan...")
                    results = UDPScan.udp_scan(target_ip, timeout, retries, filename, ftype, silent)
        except Exception as e:
            print(f"[!] ICMP scan error: {e}, trying TCP scan...")
            results = Handler.tcp_scan(target_ip, extra_tcp_flags, timeout, retries, filename, ftype)
            if not any(r['status'] == 'ACTIVE' for r in results):
                print("[!] No active hosts found with TCP, trying UDP scan...")
                results = UDPScan.udp_scan(target_ip, timeout, retries, filename, ftype, silent)

    active_hosts = [host for host in results if host["status"] == "ACTIVE"]
    return active_hosts