from .methods.protocol_scans.icmp_scan import ICMPtracert
from .methods.protocol_scans.udp_scan import UDPtracert
from .methods.protocol_scans.tcp_scan import Handler

def run(args):
    if args.method == "icmp":
        ICMPtracert.icmp_trace(args.range, args.timeout, args.retries, args.output, args.format, args.silent)
    elif args.method == "udp":
        UDPtracert.udp_trace(args.range, args.timeout, args.retries, args.output, args.format, args.silent)
    elif args.method == "tcp":
        method = Handler.parse_tcp_flags(args.extra)
        Handler.tcp_scan(args.range, method, args.timeout, args.retries, args.output, args.format)
        
        