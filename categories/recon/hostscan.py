from .methods.arp_scan import arp_scan
from .methods.tcp_scan import parse_tcp_flags,tcp_scan

def run(args):
    if not args.method:
        print("[!] Error: No method specified for hostscan.")
        return

    method = args.method.lower()

    if method == "arp":
        try:
            results = arp_scan(args)
        except RuntimeError as e:
            if "winpcap is not installed" in str(e).lower():
                print("[!] Npcap/WinPcap not found or not installed properly.")
                print("[*] Falling back to ICMP scan...")
            else:
                raise
    elif method == "tcp":
        tcp_flags = parse_tcp_flags(args.extra)
        results = tcp_scan(args.range, tcp_flags)