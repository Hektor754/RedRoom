import dns.resolver
import dns.query
import dns.zone
import dns.exception
import socket
import argparse

class Lookup:
    
    @staticmethod
    def parse_dns_flags(extra_args):
        parser_dnsenum = argparse.ArgumentParser(prog="dnsenum", add_help=False)
        parser_dnsenum.add_argument('--subdomains', action='store_true', help='Perform subdomain enumeration')
        parser_dnsenum.add_argument('--method', choices=['passive', 'brute'], default='passive')
        
        args, unknown = parser_dnsenum.parse_known_args(extra_args)
        
        if unknown:
            print(f"[!] Warning: Unknown DNS enumeration options ignored: {unknown}")
        
        return args
            
    @staticmethod
    def forward_lookup(domain):
        try:
            return [ip.address for ip in dns.resolver.resolve(domain, 'A')]
        except Exception:
            return []

    @staticmethod
    def forward_lookup_aaaa(domain):
        try:
            return [ip.address for ip in dns.resolver.resolve(domain, 'AAAA')]
        except Exception:
            return []

    @staticmethod
    def get_srv_records(domain):
        try:
            answers = dns.resolver.resolve(domain, 'SRV')
            return [(r.priority, r.weight, r.port, r.target.to_text()) for r in answers]
        except Exception:
            return []

    @staticmethod
    def attempt_zone_transfer(domain):
        results = {}
        try:
            ns_records = [ns.to_text() for ns in dns.resolver.resolve(domain, 'NS')]
        except Exception:
            return results

        for ns in ns_records:
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
                if zone is None:
                    continue
                results[ns] = []
                for name, node in zone.nodes.items():
                    results[ns].append(name.to_text())
            except dns.exception.DNSException:
                continue
        return results
                    
    @staticmethod
    def get_ns_records(domain):
        try:
            return [ns.to_text() for ns in dns.resolver.resolve(domain, 'NS')]
        except Exception:
            return []

    @staticmethod
    def get_mx_records(domain):
        try:
            return sorted([(r.preference, r.exchange.to_text()) for r in dns.resolver.resolve(domain, 'MX')])
        except Exception:
            return []
        
    @staticmethod
    def get_txt_records(domain):
        try:
            return [r.to_text().strip('"') for r in dns.resolver.resolve(domain, 'TXT')]
        except Exception:
            return []
        
    @staticmethod
    def get_cname(domain):
        try:
            return dns.resolver.resolve(domain, 'CNAME')[0].to_text()
        except Exception:
            return None

    @staticmethod
    def get_soa_record(domain):
        try:
            r = dns.resolver.resolve(domain, 'SOA')[0]
            return {
                'mname': r.mname.to_text(),
                'rname': r.rname.to_text(),
                'serial': r.serial
            }
        except Exception:
            return {}
        
    @staticmethod    
    def reverse_lookup(ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None