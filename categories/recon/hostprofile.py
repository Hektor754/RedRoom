import ipaddress
from .methods.auto_host import auto_hostdiscovery
from .methods.vendor_lookup import load_oui, lookup_vendor
from utils import print_hostprofile_results
from .methods.port_service_guess import quick_tcp_scan
from .methods.os_detection import OSDetector

class TCPFlags:
    def __init__(self, ports=None, stealth=False):
        self.port = ports
        self.stealth = stealth

common_ports = [20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123, 135, 137, 138, 
                139, 143, 161, 162, 179, 194, 389, 443, 445, 465, 514, 515, 520, 587, 631, 
                636, 993, 995, 1080, 1433, 1434, 1521, 1701, 1812, 1813, 2049, 2082, 2083, 
                2100, 2483, 2484, 3306, 3389, 3690, 4000, 4444, 5000, 5060, 5432, 5900, 5985, 
                5986, 6379, 6667, 8000, 8080, 8443, 8888, 9000, 9200, 9300, 11211, 27017, 50000]

efficient_ports = [22, 80, 443, 53, 139, 445, 3306, 8080, 21, 25]

extra_tcp_flags = TCPFlags(ports=efficient_ports, stealth=False)

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
    active_hosts = auto_hostdiscovery(args.range, args.timeout, args.retries, args.output, args.format, args.silent, extra_tcp_flags)
    oui_map = load_oui("oui.txt")
    for host in active_hosts:
        mac = host.get("mac", "").strip().lower()
        if mac and mac != "unknown":
            vendor = lookup_vendor(mac, oui_map)
            host["vendor"] = vendor
        ports, services = quick_tcp_scan(host["ip"],common_ports, args.timeout)
        host["ports"] = ports
        host["services"] = services
        os_detector = OSDetector()
        os_result = os_detector.run(host["ip"])
        best_guess_os = os_result['common_matches'][0] if os_result['common_matches'] else os_result['window_result'][2][0]

        host["os_guess"] = best_guess_os
        host["confidence"] = os_result['overall_confidence']


    print_hostprofile_results(active_hosts)