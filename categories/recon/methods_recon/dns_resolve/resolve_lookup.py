from ipwhois import IPWhois
import dns.resolver
import dns.query
import dns.zone
import dns.exception
import socket
import re

class Lookup:
    @staticmethod
    def ip_asn_lookup(ip):
        try:
            obj = IPWhois(ip)
            result = obj.lookup_rdap()
            return {
                "ip": ip,
                "asn": result.get("asn"),
                "asn_description": result.get("asn_description"),
                "asn_country_code": result.get("asn_country_code"),
                "network_name": result.get("network", {}).get("name"),
                "network_cidr": result.get("network", {}).get("cidr"),
            }
        except Exception as e:
            print(f"[-] ASN lookup failed for {ip}: {e}")
            return None
    
    @staticmethod
    def ips_whois_server_lookup(ips):
        try:
            for ip in ips:
                obj = IPWhois(ip)
                result = obj.lookup_rdap()
                return {
                    "asn": result.get("asn"),
                    "asn_description": result.get("asn_description"),
                    "asn_country_code": result.get("asn_country_code"),
                    "network_name": result.get("network", {}).get("name"),
                    "network_range": result.get("network", {}).get("cidr"),
                    "org": result.get("network", {}).get("org"),
                    "country": result.get("network", {}).get("country"),
                }
        except Exception as e:
            return {"error": str(e)}
        
    @staticmethod
    def domain_whois_server_lookup(domain):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("whois.iana.org", 43))
            s.send((domain + "\r\n").encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            s.close()

            match = re.search(r"refer:\s*(\S+)", response.decode())
            if not match:
                return {"error": "Could not find WHOIS server"}
            whois_server = match.group(1)

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((whois_server, 43))
            s.send((domain + "\r\n").encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data
            s.close()

            decoded = response.decode(errors="ignore")
            return {"whois_raw": decoded}

        except Exception as e:
            return {"error": str(e)}
          
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
                ns_ip_list = Lookup.forward_lookup(ns)
                for ns_ip in ns_ip_list:
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=5))
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