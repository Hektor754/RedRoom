from .methods.digital_fingerprinting.find_ports import PortScan
from utils import print_portscan_results


def run(args):
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
        results = PortScan.Scan_method_handler(args.range, tcp_flags, args.timeout, args.retries)
    except Exception as e:
        print(f"Error during port scanning: {e}")
    print_portscan_results(results)
        
            
        