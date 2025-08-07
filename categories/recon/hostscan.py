from .methods_recon.protocol_scans.arp_scan import ARPScan
from .methods_recon.protocol_scans.tcp_scan import Handler
from .methods_recon.protocol_scans.icmp_scan import ICMPScan
from .methods_recon.protocol_scans.udp_scan import UDPScan
import ipaddress

def run(args):
    if not args.method:
        method = "arp"
    else:
        method = args.method.lower()

    try:
        ipaddress.ip_network(args.range, strict=False)
    except ValueError:
        print(f"[!] Error: Invalid IP or IP range '{args.range}'")
        return

    if method == "arp":
        try:
            results = ARPScan.arp_scan(args.range,args.timeout,args.retries, args.output, args.format, args.silent)
        except RuntimeError as e:
            if "winpcap is not installed" in str(e).lower():
                print("[!] Npcap/WinPcap not found or not installed properly.")
                print("[*] Falling back to ICMP scan...")
                results = ICMPScan.icmp_scan(args.range, args.timeout, args.retries, args.output, args.format, args.silent)
                if results is None:
                    method = "tcp"
            else:
                raise
        except Exception as e:
            print(f"[!] Unexpected error during ARP scan: {e}")
    elif method == "tcp":
        tcp_flags = Handler.parse_tcp_flags(args.extra)
        try:
            results = Handler.tcp_scan(args.range, tcp_flags, args.timeout, args.retries, args.output, args.format)
            if results is None:
                method = "icmp"
        except Exception as e:
            print(f"[!] Unexpected error during TCP scan: {e}")
    elif method == "icmp":
        try:
            results = ICMPScan.icmp_scan(args.range, args.timeout, args.retries, args.output, args.format, args.silent)
            if results is None:
                method = "udp"
        except RuntimeError as e:
            print("[!] Taking too long to scan host.")
            print("[!] Host appears to be down...")
        except Exception as e:
            print(f"[!] Unexpected error during ICMP scan: {e}")
    elif method == "udp":
        try:
            results = UDPScan.udp_scan(args.range, args.timeout, args.retries, args.output, args.format, args.silent)
        except Exception as e:
            print(f"[!] Unexpected error during UDP scan: {e}")           
    else:
        print(f"[!] Unknown method '{method}'. Valid options: arp, tcp")