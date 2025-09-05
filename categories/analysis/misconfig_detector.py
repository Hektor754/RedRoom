import ipaddress
from categories.analysis.methods_analysis.config_checker import ConfigChecker
from categories.recon.methods_recon.digital_fingerprinting.find_ports import PortScan

def validate_ip_range(ip_range):
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        print(f"[!] Error: Invalid IP or IP range '{ip_range}'")
        return False
    
def run(args):

    if not validate_ip_range(args.range):
        return
    
    print("Running config checking...")
    try:
        tcp_flags = PortScan.parse_tcp_flags(args.extra)
        if tcp_flags is None:
            class DummyFlags:
                stealth = False
                fin = False
                ack = False
                xmas = False
                aggressive = False
            tcp_flags = DummyFlags()
        port_results = PortScan.Scan_method_handler(args.range, tcp_flags, args.timeout, args.retries)
    except Exception as e:
        print(f"Error during port scanning: {e}")
    if port_results:
        results = ConfigChecker.run(port_results)