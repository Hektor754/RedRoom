from termcolor import colored
from colorama import Fore,Style
from itertools import zip_longest
import csv
import json
import os
import socket
import ipaddress
import ifaddr
import subprocess
import shutil
import platform
import re

def print_welcome_stamp():
    logo = r"""                                                                                        


                                                                                                                       
                                                                                                                       
                                                                                                                       
                                                                                                                       
                                                                                                                       
                                                                                                                       
      xxxûûxxxûˆˆˆˆˆˆ³ˆ³³                                                                   ˆ³ˆ³³³³³³³ûûûûxûûûxÆÆ      
      xxxxxûûxxiˆ³ˆ³ˆˆˆˆˆ³ˆˆ                                                           ˆ³ˆˆˆˆˆ³ˆ  ³³³ˆûûûûûûûxûÆÆ      
      xxxûûxûûx³ˆˆˆ³ˆ       ³³ˆ            ˆˆˆˆ                ³      ˆˆˆ           ˆˆˆ³³³        ³³³³xûûûûûûûûÆÆ      
      xxxûûûûûxˆˆˆˆˆˆˆˆˆˆˆˆ      ˆ           ˆˆˆˆˆˆˆ³ˆ        ³ˆ    ˆˆ³          ³ˆˆˆ³         ³  ˆ³³•ûûûûûûûûxÆÆ      
      xxûxûûûûûˆÆÆÆÆÆÆÆÆˆ³³ˆˆˆˆˆ³ˆ             ³³³ˆˆˆ³ˆ       ˆˆ   ˆˆˆ        ˆˆˆˆ        ³iÆÆÆÆÆÆÆÆÆÆÆûûxûûûûûûÆ      
      xxxûxûÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆˆˆˆˆ³³ˆˆˆˆ³         ˆˆ³³ˆÆ³      ³Æ³ˆ ˆˆˆˆ      ˆˆ        •ÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆûûûûxÆ      
      xxxøÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆ³ˆˆˆ³³ˆ³³ˆˆ   ˆˆˆˆ³wÆˆ³ˆˆ³ˆˆ³Æx³ˆ³³•ˆ³         ˆ•xÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆûûûø      
      xxÆÆÆÆÆÆÆûûûûûûÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆˆˆˆˆ³³ˆˆˆˆˆ³³³ÆÆˆˆˆˆˆ³ˆˆÆÆˆ³³xxˆˆˆˆˆˆ³³ÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆæÿûûûûûûûûÆÆÆÆÆÆÆxx      
      xxxÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆ³³ˆ³³³³ÆÆÆ³ˆˆˆˆˆ³tÆÆxûxûûxxÿÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆûûûûÆÆÆÆÆÆÆûûûû      
      xxxxxÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆûûûûÿûÿÿûûÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆûxxxxû      
      xxûxûûÆÆÆÆÆÆÆÆÆÆxxûxÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÿûÿÿûÿûÿûûûÿêÆÆÆÆÆÆÆÆÆÆÆÆÆøûÆÆÆÆÆÆÆÆÆÆÆÆûxûûÆÆÆÆÆÆÆÆÆûûxûxûxû      
      xxtxxûûûûûûÆÆÆûÆxw   ÆÆÆÆÆÆÆÆÆÆ ûxûÆÆÆêÆÆÆÆÆÆÆû³³³³³ˆ³ˆ³³ÿÿÆÆÆÆÆÆÆÆÆÆÿûÿ   ÆÆÆÆÆÆÆÆÆˆ  xêûxÆÆÆÆÆûûûûûûûûxxû      
      xxx³³³³³xÿÿøÆÆÆw³ˆÆx     wx     ûûÆøøøøøøêÆÆÆÆÆ³³       ³³æÆÆÆÆÆêêêêêêÆÆxi          ³ûê³³ûÆÆÆøÿøûûû³ˆ³xxxxû      
      xxx³³³³³³iÿÿÿêÆûûÿûûÿ³³•³³³³³³³ÿÿÿÿøøøøøøêøûÿÆÆ³ˆ       ³³ÆÆÿÿøÆêêêêêøêêêêêÿˆ³³³³³³³³xêêêÆæêêêˆˆˆ³ˆ³ˆ³xxxxÆ      
      xxxx³³³³³••iÿÿÿÿûÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿûû³•³³³ûûÿ³³       ³³Æÿÿûÿÿûˆøêêêêûÿÿûêêêêêøêêêêêêêêêêê³³³³ˆˆˆˆ³xûûûxÆ      
      Æxxxx³³•³³³³³xÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿû  ³³³³³³³ûûˆ³       ³³ÿûûÿÿûû³ˆ³³³êêêÿûûûûûûûûûûøêêêêê³ˆ³³³³³³³³³xxxxÆÆ      
      ÆÆxxxxx³³³ˆ³³³³³ÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿûû   •ˆ³³³³³³³³ûˆ³       ³³ûÿûÿûûûÿ³³ˆ³³³³êêêûûûûûûûÿæøÿˆ³³³³³³ˆ³³³³ˆxxûxÆÆÆ      
      ÆÆÆxxxwx••³³³³³³•³³³iniiii³ˆ³      ˆ³³³ˆ³³³³³³³³³      ³³³ûÿûûÿûûû³³³³³ˆ³ˆ³³³³³³³³³³³ˆ³ˆ³³³ˆ³³ˆ³ˆ³xxxxxÆÆÆê      
      ÆÆÆÆwxxxxx³³³ˆ³³³³³³³³ˆ³³³         ³³³³³³³ˆ³³³³³ˆ      ³³³ÿÿûûûûûû³³ˆˆ³ˆ³ˆˆ³³³ˆ³³³³ˆ³³³³ˆˆ³³ˆˆˆˆxxxxûxÆÆÆÆæ      
      ÆÆÆÆÆxxxxxxt³³³³³³³³³³³            ³³³³³³•³³³³³ˆ³      ³³³ûÿûÿÿûûû³³³³³ˆ³³ˆˆˆ³ˆˆ³ˆ³³³³ˆ³³³³ˆ³³xxwxxxxÆÆÆÆÆÆ      
                                                                                                                       
                                                                                                                       
          ░▒▓███████▓▒░░▒▓████████▓▒░▒▓███████▓▒░░▒▓███████▓▒░░░▒▓██████▓▒░░░▒▓██████▓▒░░▒▓██████████████▓▒░░  
          ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░░░░░░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
          ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░░░░░░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
          ░▒▓███████▓▒░░▒▓██████▓▒░░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
          ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░░░░░░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
          ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░░░░░░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
          ░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░                                                                                                                  
                                                                                                                       
                                                                                                                       
                                                                                                                                                                                                                                                                         
    """

    tagline = "Recon tool inspired by the Marvel Red Room — stealth and precision."
    usage = "Usage: RedRoom -h for help"
    author = "by Nemes1s | https://github.com/Nemes1s/RedRoom"
    quote = '“In the shadows, we find the truth.”'

    print(Fore.LIGHTRED_EX + logo + Style.RESET_ALL)
    print(tagline)
    print(usage)
    print(author)
    print()
    print(quote)

def print_zone_transfer_results(results):
    if not results:
        print("[!] No zone transfer data found.")
        return

    for ns_server, records in results.items():
        print(f"\n=== Zone transfer from: {ns_server} ===")
        if not records:
            print("  No records found.")
            continue

        if isinstance(records[0], dict):
            for rec in records:
                rec_name = rec.get("name", "")
                rec_type = rec.get("type", "")
                rec_data = rec.get("records", [])
                print(f"  {rec_name:30} {rec_type:6} {', '.join(rec_data)}")
        else:
            for rec_name in records:
                print(f"  {rec_name}")

    print("\n[+] Zone transfer printing complete.\n")
       
def print_hostprofile_results(results):
    print("\n" + "=" * 60)
    for i, host in enumerate(results, 1):
        print(f"{Fore.CYAN}Host #{i}{Style.RESET_ALL}")
        print("-" * 60)

        print(f"{Fore.YELLOW}Hostname{Style.RESET_ALL}    : {host.get('hostname', 'Unknown')}")
        print(f"{Fore.YELLOW}IP{Style.RESET_ALL}          : {host.get('ip', 'Unknown')}")
        print(f"{Fore.YELLOW}MAC{Style.RESET_ALL}         : {host.get('mac', 'Unknown')}")
        print(f"{Fore.YELLOW}Vendor{Style.RESET_ALL}      : {host.get('vendor', 'Unknown')}")

        os_data = host.get('os_data', {})
        primary_guess = os_data.get('primary_guess', 'Unknown')
        confidence = os_data.get('confidence', 'unknown').lower()

        if confidence == "high":
            confidence_color = Fore.GREEN
        elif confidence == "medium":
            confidence_color = Fore.YELLOW
        else:
            confidence_color = Fore.RED

        print(f"{Fore.YELLOW}OS{Style.RESET_ALL}          : {primary_guess}")
        print(f"{Fore.YELLOW}Confidence{Style.RESET_ALL}  : {confidence_color}{confidence.upper()}{Style.RESET_ALL}")

        if os_data.get('alternatives'):
            print(f"{Fore.YELLOW}Also Possible{Style.RESET_ALL}: {', '.join(os_data['alternatives'])}")

        if os_data.get('window_size') and os_data.get('ttl'):
            print(f"{Fore.YELLOW}Detection{Style.RESET_ALL}   : Window={os_data['window_size']}, TTL={os_data['ttl']}")

        status = host.get('status', 'INACTIVE').upper()
        status_color = Fore.GREEN if status == "ACTIVE" else Fore.RED
        print(f"{Fore.YELLOW}Status{Style.RESET_ALL}      : {status_color}{status}{Style.RESET_ALL}")

        ports = host.get('ports', [])
        services = host.get('services', [])

        if ports:
            print(f"{Fore.YELLOW}Open Ports{Style.RESET_ALL}:")
            for port, service in zip(ports, services):
                print(f"  {Fore.BLUE}{port:<5}{Style.RESET_ALL} {service}")
        else:
            print(f"{Fore.YELLOW}Open Ports{Style.RESET_ALL}: None detected")

        print("=" * 60)

def print_summary(results,scantype):
    total = len(results)
    active_hosts = sum(1 for r in results if r["status"] == "ACTIVE")
    down_hosts = total - active_hosts

    print(f"\n {scantype} scan summary: ")
    print(f"-Total hosts scanned: {total}")
    print(f"-Hosts active: {active_hosts}")
    print(f"-Hosts inactive: {down_hosts}")

def print_sub_passive_results(results):
    all_subdomains = results.get("all", [])
    per_source = results.get("per_source", {})

    print("\n" + "=" * 60)
    print(f"[+] Total Unique Subdomains Found: {len(all_subdomains)}")
    print("=" * 60 + "\n")

    for source, subdomains in per_source.items():
        count = len(subdomains)
        print(f"  [•] {source.capitalize():<15} → {count} subdomain{'s' if count != 1 else ''}")

    print("\n" + "-" * 60)
    print("[+] Combined Subdomains List:")
    print("-" * 60 + "\n")

    for sub in sorted(all_subdomains):
        print(f"  - {sub}")

    print("\n" + "=" * 60 + "\n")

def print_sub_brute_results(domain, found_subdomains, total_attempts):
    print("\n" + "=" * 60)
    print(f"[+] Brute-Force Subdomain Enumeration Results for: {domain}")
    print("=" * 60)
    
    print(f"[•] Total Attempts Made: {total_attempts}")
    print(f"[•] Total Valid Subdomains Found: {len(found_subdomains)}")
    
    if found_subdomains:
        print("\n" + "-" * 60)
        print("[+] Discovered Subdomains:")
        print("-" * 60)
        for sub in sorted(found_subdomains):
            print(f"  └─ {sub}")
    else:
        print("\n[-] No subdomains found via brute-force.")

    print("=" * 60 + "\n")
    
    
def sanitize_results(results):
    sanitized = {}
    for key, val in results.items():
        if val is None:
            sanitized[key] = []
        else:
            sanitized[key] = val
    return sanitized

def save_results_json(results,filename):
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Results saved to {filename}")

def save_dns_results_json(results, filename):
    results = sanitize_results(results)
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] DNS results saved to {filename}")

def save_results_json_brute(results, filename):
    found_subdomains, wordlist_count = results
    data = {
        "wordlist_count": wordlist_count,
        "subdomains_found_count": len(found_subdomains),
        "subdomains": found_subdomains
    }
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"\n[+] Brute force results saved to {filename}")

def save_results_csv(results, filename):
    with open(filename, mode="w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["hostname", "ip", "status"])
        writer.writeheader()
        writer.writerows(results)
    print(f"\n[+] results saved to {filename}")
    
def save_dns_results_csv(results, filename):
    results = sanitize_results(results)
    flat_records = []

    for record_type, value in results.items():
        if isinstance(value, list):
            for entry in value:
                flat_records.append({
                    "record_type": record_type,
                    "value": str(entry)
                })
        elif isinstance(value, dict):
            flat_records.append({
                "record_type": record_type,
                "value": json.dumps(value)
            })
        else:
            flat_records.append({
                "record_type": record_type,
                "value": str(value)
            })

    with open(filename, mode="w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["record_type", "value"])
        writer.writeheader()
        writer.writerows(flat_records)

    print(f"\n[+] DNS results saved to {filename}")
    
def save_subenum_results_csv_brute(results, filename):
    found_subdomains, wordlist_count = results
    with open(filename, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([f"Total wordlist entries: {wordlist_count}"])
        writer.writerow([f"Total subdomains found: {len(found_subdomains)}"])
        writer.writerow([])
        writer.writerow(["Subdomains Found"])
        
        for sub in found_subdomains:
            writer.writerow([sub])
    print(f"\n[+] Brute force results saved to {filename}")
    
def save_trrt_results_csv(results, filename):
    with open(filename, mode="w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["hop", "ip", "latency"])
        writer.writeheader()
        writer.writerows(results)
    print(f"\n[+] results saved to {filename}")
    
def save_subenum_results_csv(results, filename):
    sources = list(results.get("per_source", {}).keys())
    columns = [results["per_source"].get(src, []) for src in sources]

    rows = zip_longest(*columns, fillvalue="")

    with open(filename, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(sources)
        for row in rows:
            writer.writerow(row)
    print(f"\n[+] Results saved to {filename}")
        
def handle_scan_output(results, scantype, filename=None, ftype=None):
    if scantype not in ("dnsenum", "traceroute"):
        print_summary(results, scantype=scantype)

    if ftype and not filename:
        filename = f"scan_output.{ftype}"

    if filename and not ftype:
        ext = os.path.splitext(filename)[1].lower()
        if ext == ".csv":
            ftype = "csv"
        elif ext == ".json":
            ftype = "json"

    if filename:
        if scantype == "dnsenum":
            results = sanitize_results(results)
            if ftype not in ("csv", "json"):
                print(f"[!] Unsupported output format: {ftype}")
            elif ftype == "csv":
                save_dns_results_csv(results, filename)
            elif ftype == "json":
                save_dns_results_json(results, filename)
        elif scantype == "traceroute":
            if ftype not in ("csv", "json"):
                print(f"[!] Unsupported output format: {ftype}")
            elif ftype == "csv":
                save_trrt_results_csv(results, filename)
            elif ftype == "json":
                save_results_json(results, filename) 
        elif scantype == "subenum":
            if ftype not in ("csv", "json"):
                print(f"[!] Unsupported output format: {ftype}")
            else:
                if isinstance(results, dict) and "all" in results and "per_source" in results:
                    if ftype == "csv":
                        save_subenum_results_csv(results, filename)
                    else:
                        save_results_json(results, filename)
                elif isinstance(results, tuple) and len(results) == 2:
                    if ftype == "csv": 
                        save_subenum_results_csv_brute(results, filename)
                    else: 
                        save_results_json_brute(results, filename)
                else:
                    print("[!] Unknown results format, cannot save.")           
        else:
            if ftype not in ("csv", "json"):
                print(f"[!] Unsupported output format: {ftype}")
            elif ftype == "csv":
                save_results_csv(results, filename)
            elif ftype == "json":
                save_results_json(results, filename)
            
        

def resolve_hostname(target_ip):
    if isinstance(target_ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        target_ip = str(target_ip)

    try:
        target_addr = ipaddress.ip_address(target_ip)
    except ValueError:
        return "Invalid IP"
    
    def mdns_lookup():
        if shutil.which("avahi-resolve-address") is None:
            return "Unknown"
        try:
            output = subprocess.check_output(
                ["avahi-resolve-address", target_ip],
                stderr=subprocess.DEVNULL,
                timeout=2,
                encoding='utf-8'                
            )
            parts = output.strip().split()
            if len(parts) >= 2:
                return parts[1]
        except Exception:
            pass
        return None

    def netbios_lookup_nmblookup():
        if shutil.which("nmblookup") is None:
            return None
        adapters = ifaddr.get_adapters()
        for adapter in adapters:
            for ip in adapter.ips:
                if not isinstance(ip.ip, str):
                    continue
                try:
                    network = ipaddress.ip_network(f"{ip.ip}/{ip.network_prefix}", strict=False)
                except ValueError:
                    continue
                if target_addr in network:
                    try:
                        output = subprocess.check_output(
                            ['nmblookup', '-A', target_ip],
                            stderr=subprocess.DEVNULL,
                            timeout=3
                        ).decode(errors='ignore')
                        for line in output.splitlines():
                            if '<00>' in line and 'GROUP' not in line:
                                parts = line.strip().split()
                                if parts:
                                    return parts[0]
                    except Exception:
                        continue
        return None

    def netbios_lookup_nbtstat():
        if platform.system() != "Windows":
            return None
        try:
            output = subprocess.check_output(
                ['nbtstat', '-A', target_ip],
                stderr=subprocess.DEVNULL,
                timeout=3,
                encoding='utf-8',
                errors='ignore'
            )
            for line in output.splitlines():
                if '<00>' in line and 'UNIQUE' in line.upper():
                    parts = re.split(r'\s+', line.strip())
                    if parts:
                        return parts[0]
        except Exception:
            return None
        return None

    try:
        hostname, _, _ = socket.gethostbyaddr(target_ip)
        if hostname:
            return hostname
    except Exception:
        pass

    hostname = netbios_lookup_nmblookup()
    if hostname:
        return hostname

    hostname = netbios_lookup_nbtstat()
    if hostname:
        return hostname
    
    hostname = mdns_lookup()
    if hostname:
        return hostname

    try:
        fqdn = socket.getfqdn(target_ip)
        if fqdn and fqdn != target_ip:
            hostname = fqdn
            return hostname
    except Exception:
        pass

    return "Unknown"