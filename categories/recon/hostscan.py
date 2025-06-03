from .methods.arp_scan import arp_scan
from .methods.tcp_scan import parse_tcp_flags, tcp_scan
from .methods.icmp_scan import icmp_scan
import ipaddress

def run(args):
    if not args.method:
        print("[!] Error: No method specified for hostscan. Use -m with one of: arp, tcp")
        return

    method = args.method.lower()

    try:
        ipaddress.ip_network(args.range, strict=False)
    except ValueError:
        print(f"[!] Error: Invalid IP or IP range '{args.range}'")
        return

    if method == "arp":
        try:
            results = arp_scan(args.range,args.timeout,args.retries, args.output, args.format)
        except RuntimeError as e:
            if "winpcap is not installed" in str(e).lower():
                print("[!] Npcap/WinPcap not found or not installed properly.")
                print("[*] Falling back to ICMP scan...")
                results = icmp_scan(args.range, args.timeout, args.retries, args.output, args.format)
            else:
                raise
        except Exception as e:
            print(f"[!] Unexpected error during ARP scan: {e}")
    elif method == "tcp":
        tcp_flags = parse_tcp_flags(args.extra)
        try:
            results = tcp_scan(args.range, tcp_flags, args.timeout, args.retries, args.output, args.format)
        except Exception as e:
            print(f"[!] Unexpected error during TCP scan: {e}")
    elif method == "icmp":
        try:
            results = icmp_scan(args.range, args.timeout, args.retries, args.output, args.format)
        except RuntimeError as e:
            print("[!] Taking too long to scan host.")
            print("[!] Host appears to be down...")
        except Exception as e:
            print(f"[!] Unexpected error during ICMP scan: {e}")

    else:
        print(f"[!] Unknown method '{method}'. Valid options: arp, tcp")