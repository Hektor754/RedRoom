from .methods.arp_scan import arp_scan

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