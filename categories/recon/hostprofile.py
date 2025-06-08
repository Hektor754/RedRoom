import ipaddress
from .methods.auto_host import auto_hostdiscovery
from .methods.vendor_lookup import load_oui, lookup_vendor
from utils import print_hostprofile_results

def run(args):
    if args.method:
        print("[!] Invalid input: hostprofile does not require a method.")
        return
    
    try:
        ipaddress.ip_network(args.range, strict=False)
    except ValueError:
        print(f"[!] Error: Invalid IP or IP range '{args.range}'")
        return
    
    args.silent = True
    active_hosts = auto_hostdiscovery(args.range, args.timeout, args.retries, args.output, args.format, args.silent, extra_tcp_flags=None)
    oui_map = load_oui("oui.txt")
    for host in active_hosts:
        mac = host.get("mac", "").strip().lower()
        if mac and mac != "unknown":
            vendor = lookup_vendor(mac, oui_map)
            host["vendor"] = vendor
    print_hostprofile_results(active_hosts)