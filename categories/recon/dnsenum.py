import ipaddress
from .methods.dns_resolve.resolve_lookup import Lookup

def parse_ips(ip_range):
    try:
        net = ipaddress.ip_network(ip_range, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [ip_range]

def run(args):
    if args.domain:
        domain = args.domain
        print(f"[+] A Records (Forward lookup) for {domain}")
        ips = Lookup.forward_lookup(domain)
        for ip in ips:
            print(f"  - {ip}")

        print(f"\n[+] CNAME Record")
        cname = Lookup.get_cname(domain)
        print(f"  - {cname}" if cname else "  - None")

        print(f"\n[+] NS Records")
        for ns in Lookup.get_ns_records(domain):
            print(f"  - {ns}")

        print(f"\n[+] MX Records")
        for mx in Lookup.get_mx_records(domain):
            print(f"  - {mx[1]} (priority {mx[0]})")

        print(f"\n[+] TXT Records")
        for txt in Lookup.get_txt_records(domain):
            print(f"  - {txt}")

        print(f"\n[+] SOA Record")
        soa = Lookup.get_soa_record(domain)
        if soa:
            print(f"  - MNAME: {soa['mname']}")
            print(f"  - RNAME: {soa['rname']}")
            print(f"  - Serial: {soa['serial']}")
        else:
            print("  - None")

        print(f"\n[+] Reverse Lookup (PTR) for resolved IPs")
        for ip in ips:
            rev = Lookup.reverse_lookup(ip)
            print(f"  - {ip} => {rev if rev else 'N/A'}")

    elif args.range:
        ips = parse_ips(args.range)
        print(f"[+] Reverse Lookup (PTR) for IPs in range {args.range}")
        for ip in ips:
            rev = Lookup.reverse_lookup(ip)
            print(f"  - {ip} => {rev if rev else 'N/A'}")
    else:
        print("[!] Error: No domain or IP specified for dnsenum. Use -d or -r with a domain name or IP.")
