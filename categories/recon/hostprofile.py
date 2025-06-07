import ipaddress
from .methods.auto_host import auto_hostdiscovery
from .methods.vendor_lookup import load_oui, lookup_vendor

def run(args):
    if args.method:
        print("[!] Invalid input: hostprofile does not require a method.")
        return
    
    try:
        ipaddress.ip_network(args.range, strict=False)
    except ValueError:
        print(f"[!] Error: Invalid IP or IP range '{args.range}'")
        return
    
    active_hosts = auto_hostdiscovery(args.range, timeout=1.0, retries=1, filename=None, ftype=None, extra_tcp_flags=None)
    oui_map = load_oui("oui.txt")

    for host in active_hosts:
        mac = host["mac"]
        vendor = lookup_vendor(mac,oui_map)
        host["vendor"] = vendor
        #TODO make mac scan here and append mac and vendor to existing dictionary