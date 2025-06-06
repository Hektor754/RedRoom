import ipaddress
from .methods import auto_host

def run(args):
    if args.method:
        print("[!] Invalid input: hostprofile does not require a method.")
        return
    
    try:
        ipaddress.ip_network(args.range, strict=False)
    except ValueError:
        print(f"[!] Error: Invalid IP or IP range '{args.range}'")
        return
    
    active_hosts = auto_host(args.range, timeout=1.0, retries=1, filename=None, ftype=None, extra_tcp_flags=None)