import requests
from requests.exceptions import SSLError
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
import socket

SUBDOMAIN_SOURCES = {
    "crtsh": "https://crt.sh/?q=%25.{domain}&output=json",
    "threatcrowd": "https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}",
    "alienvault": "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
    "virustotal": "https://www.virustotal.com/api/v3/domains/{domain}/subdomains",
    "securitytrails": "https://api.securitytrails.com/v1/domain/{domain}/subdomains",
    "dnsdumpster": "https://dnsdumpster.com/",
    "certspotter": "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
}

class Subdomain_Lookup:
    
    @staticmethod
    def bruteforce(domain, wordlist, max_workers=30):
        found = set()
        with open(wordlist, 'r') as f:
            sub_names = [line.strip() for line in f if line.strip()]

        print(f"Starting brute force on {domain} with {len(sub_names)} entries...")

        def check_subdomain(sub):
            full_domain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                return full_domain, ip
            except socket.gaierror:
                return None

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [executor.submit(check_subdomain, sub) for sub in sub_names]

            for future in as_completed(futures):
                result = future.result()
                if result:
                    full_domain, ip = result
                    print(f"[FOUND] {full_domain} -> {ip}")
                    found.add(full_domain)

        return sorted(found), len(sub_names)

    @staticmethod
    def run(arguments, domain, api_keys=None):
        all_subdomains = set()
        source_data = {}
        api_keys = api_keys or {}

        for argument in arguments:
            scan = SOURCES.get(argument)
            if not scan:
                print(f"[!] Warning: No scan function found for source '{argument}'")
                continue

            try:
                if argument in api_keys and api_keys[argument]:
                    subdomains = scan(domain, api_keys[argument])
                else:
                    subdomains = scan(domain)
                    
                subdomains = set(subdomains)
                source_data[argument] = subdomains
                all_subdomains.update(subdomains)
            except Exception as e:
                print(f"[!] Error running scan for {argument}: {e}")

        return {
            "all": sorted(all_subdomains),
            "per_source": source_data
        }
        
    @staticmethod
    def get_from_crtsh(domain):
        url = SUBDOMAIN_SOURCES["crtsh"].format(domain=domain)
        retries = 3
        for i in range(retries):
            try:
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                data = response.json()

                subdomains = set()
                for entry in data:
                    names = entry.get("name_value", "").split("\n")
                    for sub in names:
                        sub = sub.strip().lower()
                        if sub.endswith(domain):
                            subdomains.add(sub)

                return sorted(subdomains)
            except requests.exceptions.HTTPError as e:
                if response.status_code == 503 and i < retries - 1:
                    print(f"[!] crt.sh service unavailable, retrying ({i+1}/{retries})...")
                    time.sleep(5)
                    continue
                else:
                    print(f"[!] crt.sh error: {e}")
                    return []
            except Exception as e:
                print(f"[!] crt.sh error: {e}")
                return []

    @staticmethod
    def get_from_threatcrowd(domain):
        url = SUBDOMAIN_SOURCES["threatcrowd"].format(domain=domain)
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()

            subdomains = data.get("subdomains", [])
            cleaned = set()

            for sub in subdomains:
                sub = sub.strip().lower()
                if sub.endswith(domain):
                    cleaned.add(sub)

            return sorted(cleaned)

        except SSLError as ssl_err:
            print(f"[!] ThreatCrowd SSL certificate verification failed: {ssl_err}")
            return []
        except Exception as e:
            print(f"[!] ThreatCrowd error: {e}")
            return []

    @staticmethod
    def get_from_alienvault(domain, api_key=None):
        url = SUBDOMAIN_SOURCES["alienvault"].format(domain=domain)
        headers = {}
        if api_key:
            headers['X-OTX-API-KEY'] = api_key

        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()

            subdomains = set()
            passive_dns = data.get("passive_dns", [])

            for entry in passive_dns:
                hostname = entry.get("hostname", "").strip().lower()
                if hostname.endswith(domain):
                    subdomains.add(hostname)

            return sorted(subdomains)

        except Exception as e:
            print(f"[!] AlienVault error: {e}")
            return []

    @staticmethod
    def get_from_virustotal(domain, api_key=None):
        if not api_key:
            print("[!] VirusTotal API key not provided.")
            return []

        url = SUBDOMAIN_SOURCES["virustotal"].format(domain=domain)
        headers = {
            "x-apikey": api_key
        }

        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()

            subdomains = set()
            for item in data.get("data", []):
                attributes = item.get("attributes", {})
                subs = attributes.get("subdomains", [])
                for sub in subs:
                    sub = sub.strip().lower()
                    if sub.endswith(domain):
                        subdomains.add(sub)

            return sorted(subdomains)

        except Exception as e:
            print(f"[!] VirusTotal error: {e}")
            return []

    @staticmethod
    def get_from_securitytrails(domain, api_key=None):
        if not api_key:
            print("[!] SecurityTrails API key not provided.")
            return []

        url = SUBDOMAIN_SOURCES["securitytrails"].format(domain=domain)
        headers = {
            "APIKEY": api_key
        }

        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()

            subdomains = set()
            for sub in data.get("subdomains", []):
                full_sub = f"{sub}.{domain}".lower()
                subdomains.add(full_sub)

            return sorted(subdomains)

        except Exception as e:
            print(f"[!] SecurityTrails error: {e}")
            return [] 

    @staticmethod
    def get_from_certspotter(domain):
        url = SUBDOMAIN_SOURCES["certspotter"].format(domain=domain)
        subdomains = set()
        try:
            page = 1
            while True:
                paged_url = f"{url}&page={page}"
                response = requests.get(paged_url, timeout=10)
                response.raise_for_status()
                data = response.json()
                if not data:
                    break
                
                for cert in data:
                    dns_names = cert.get("dns_names", [])
                    for name in dns_names:
                        name = name.lower()
                        if name.endswith(domain):
                            subdomains.add(name)

                if len(data) < 100:
                    break
                page += 1
                
            return sorted(subdomains)

        except Exception as e:
            print(f"[!] CertSpotter error: {e}")
            return []     
        
SOURCES = {
    "crtsh": Subdomain_Lookup.get_from_crtsh,
    "threatcrowd": Subdomain_Lookup.get_from_threatcrowd,
    "alienvault": Subdomain_Lookup.get_from_alienvault,
    "virustotal": Subdomain_Lookup.get_from_virustotal,
    "securitytrails": Subdomain_Lookup.get_from_securitytrails,
    "certspotter": Subdomain_Lookup.get_from_certspotter,
}    