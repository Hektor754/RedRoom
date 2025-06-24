from .methods.protocol_scans.icmp_scan import ICMPtracert
from .methods.protocol_scans.udp_scan import UDPtracert

def run(args):
    if args.method == "icmp":
        ICMPtracert.icmp_trace(args.range, args.timeout, args.retries, args.output, args.format, args.silent)
    elif args.method == "udp":
        UDPtracert.udp_trace(args.range, args.timeout, args.retries, args.output, args.format, args.silent)
        