import ipaddress
import argparse
from .methods.dns_resolve.resolve_lookup import Lookup
from .methods.dns_resolve.subdomain_resolve import Subdomain_Lookup
from utils import handle_scan_output,print_zone_transfer_results,print_whois_results,print_asn_results
import traceback

DNS_RECORDS = {
    'A': (Lookup.forward_lookup, True),
    'AAAA': (Lookup.forward_lookup_aaaa, True),
    'NS': (Lookup.get_ns_records, True),
    'MX': (Lookup.get_mx_records, True),
    'CNAME': (Lookup.get_cname, False),
    'TXT': (Lookup.get_txt_records, True),
    'SOA': (Lookup.get_soa_record, False),
    'SRV': (Lookup.get_srv_records, True)
}

MODES = {
    'min': ['A', 'AAAA', 'NS'],
    'average': ['A', 'AAAA', 'MX', 'NS', 'CNAME'],
    'full': list(DNS_RECORDS.keys()),
}

def parse_ips(ip_range):
    try:
        net = ipaddress.ip_network(ip_range, strict=False)
        return [str(ip) for ip in net.hosts()]
    except ValueError:
        return [ip_range]

def run(args):

    if not args.domain:
        print("[!] Error: No domain specified")
        return

    domain = args.domain
    ips = parse_ips(args.range)
    
    if args.whois:
        if domain:
            results = Lookup.domain_whois_server_lookup(domain)
        elif ips:
            results = Lookup.ips_whois_server_lookup(ips)
        print_whois_results(results)         
    elif args.asn:
        results = Lookup.ip_asn_lookup(ips)
        print_asn_results(results)
    handle_scan_output(dns_results, scantype="dnsenum", filename=args.output, ftype=args.format)
        
    if args.zonetransfer:
        try:
            results = Lookup.attempt_zone_transfer(domain)
        except Exception:
            print("[!] Unexpected error during scan:")
            traceback.print_exc()
        if results:
            for ns, recs in results.items():
                print(f"  - Zone transfer successful from {ns}:")
                for r in recs:
                    print(f"    - {r}")
        else:
            print("  - Zone transfer unsuccessful or denied")
            return
        print_zone_transfer_results(results)
        handle_scan_output(results, scantype="dnsenum", filename=args.output, ftype=args.format)
        return

    if args.min:
        records_to_query = MODES['min']
    elif args.full:
        records_to_query = MODES['full']
    else:
        records_to_query = MODES['average']

    dns_results = {}

    for record in records_to_query:
        lookup_func, is_list = DNS_RECORDS[record]
        print(f"\n[+] {record} Record(s) for {domain}")
        
        try:
            results = lookup_func(domain)
            dns_results[record] = results
        except Exception as e:
            print(f"  [!] Error querying {record} records: {e}")
            dns_results[record] = None
            continue

        if results is None or (is_list and len(results) == 0):
            print("  - None")
            dns_results[record] = None
            continue

        if not results:
            print("  - None")
            continue

        if is_list:
            if record == 'MX':
                for pref, exch in results:
                    print(f"  - {exch} (priority {pref})")
            else:
                for item in results:
                    print(f"  - {item}")
        else:
            if record == 'SOA':
                print(f"  - MNAME: {results.get('mname')}")
                print(f"  - RNAME: {results.get('rname')}")
                print(f"  - Serial: {results.get('serial')}")
            else:
                print(f"  - {results}")

    if 'A' in records_to_query:
        ips = Lookup.forward_lookup(domain)
        ptr_results = {}
        for ip in ips:
            rev = Lookup.reverse_lookup(ip)
            ptr_results[ip] = rev if rev else "N/A"
            print(f"  - {ip} => {rev if rev else 'N/A'}")
        dns_results["PTR"] = ptr_results

        handle_scan_output(dns_results, scantype="dnsenum", filename=args.output, ftype=args.format)