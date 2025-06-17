import dns.resolver
import socket

class Lookup:

    @staticmethod
    def forward_lookup(domain):
        try:
            return [ip.address for ip in dns.resolver.resolve(domain, 'A')]
        except Exception:
            return []
        
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