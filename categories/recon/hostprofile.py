import ipaddress
from .methods_recon.digital_fingerprinting.auto_host import auto_hostdiscovery
from .methods_recon.digital_fingerprinting.vendor_lookup import load_oui, lookup_vendor
from utils import print_hostprofile_results
from .methods_recon.digital_fingerprinting.find_ports import PortScan
from .methods_recon.digital_fingerprinting.os_detection import OSDetector
from argparse import Namespace

common_ports = [
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 119, 123, 135, 137, 138, 
    139, 143, 161, 162, 179, 194, 389, 443, 445, 465, 514, 515, 520, 587, 631, 
    636, 993, 995, 1080, 1433, 1434, 1521, 1701, 1812, 1813, 2049, 2082, 2083, 
    2100, 2483, 2484, 3306, 3389, 3690, 4000, 4444, 5000, 5060, 5432, 5900, 5985, 
    5986, 6379, 6667, 8000, 8080, 8443, 8888, 9000, 9200, 9300, 11211, 27017, 50000
]

efficient_ports = [
    22, 80, 443, 53, 139, 445, 3306, 8080, 21, 25,
    3389, 1433, 5432
]

extra_tcp_flags = Namespace(
    port=efficient_ports,
    stealth=False,
    fin=False,
    ack=False
)

def validate_ip_range(ip_range):
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        print(f"[!] Error: Invalid IP or IP range '{ip_range}'")
        return False

def enhance_host_information(host, oui_map, timeout):
    mac = host.get("mac", "").strip().lower()
    if mac and mac != "unknown":
        host["vendor"] = lookup_vendor(mac, oui_map)

    results = PortScan.Scan_method_handler(host["ip"], timeout)
    for scan_type, scan_results in results.items():
        for result in scan_results:
            if result["ip"] == host["ip"]:
                host["ports"] = result["open_ports"]
                host["services"] = result["services"]

    try:
        os_detector = OSDetector()
        os_result = os_detector.run(host["ip"])
        
        host["os_data"] = {
            "primary_guess": os_result.get("primary_guess", "Unknown"),
            "confidence": os_result.get("confidence", "Unknown"),
            "alternatives": os_result.get("alternatives", []),
            "window_size": os_result.get("window_size"),
            "ttl": os_result.get("ttl")
        }
        
        primary = host["os_data"]["primary_guess"]
        alternatives = host["os_data"]["alternatives"]
        print(primary)
        print(alternatives)
        
        if primary.lower() == "unknown" and alternatives:
            host["os_data"]["primary_guess"] = alternatives.pop(0)
            if len(alternatives) > 0:
                host["os_data"]["alternatives"] = alternatives
            else:
                host["os_data"]["alternatives"] = []
        else:
            host["os_data"]["primary_guess"] = primary
            host["os_data"]["alternatives"] = alternatives
        
    except Exception as e:
        host["os_guess"] = "Detection failed"
        host["confidence"] = "low"
        host["os_data"] = {"error": str(e)}


def run(args):
    if args.method:
        print("[!] Invalid input: hostprofile does not require a method.")
        return
    
    if not validate_ip_range(args.range):
        return

    args.silent = True

    active_hosts = auto_hostdiscovery(
        args.range, 
        args.timeout, 
        args.retries, 
        args.output, 
        args.format, 
        args.silent, 
        extra_tcp_flags
    )
    
    if not active_hosts:
        print("[!] No active hosts found")
        return

    try:
        oui_map = load_oui("oui.txt")
    except Exception as e:
        print(f"[!] Failed to load OUI database: {str(e)}")
        oui_map = {}

    for host in active_hosts:
        enhance_host_information(host, oui_map, args.timeout)

    print_hostprofile_results(active_hosts)