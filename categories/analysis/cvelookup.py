from categories.recon.methods_recon.digital_fingerprinting.find_ports import PortScan
from categories.analysis.methods_analysis.cve_scan import CVE_Scan
from Essentials.utils import print_cve_matches,handle_scan_output

def run(args):
    scantype = "cvelookup"
    class DummyFlags:
        stealth = False
        fin = False
        ack = False
        xmas = False
        aggressive = False
    tcp_flags = DummyFlags()
    results = PortScan.Scan_method_handler(args.range, tcp_flags, args.timeout, args.retries)
    if results:
        matches = CVE_Scan.scan_handler(results)

        if matches:
            print_cve_matches(matches)
            handle_scan_output(matches, scantype, filename=args.output, ftype=args.format)
