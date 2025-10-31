import argparse

def add_common_args(parser):
    """Adds common arguments shared across all tools."""
    parser.add_argument('--timeout', type=float, default=2.0,
                        help='Timeout in seconds to wait for each probe (default: 2.0)')
    parser.add_argument('--retries', type=int, default=2,
                        help='Number of retries if no response (default: 2)')
    parser.add_argument('--output', type=str, default=None,
                        help='Output to save results on a file')
    parser.add_argument('--format', choices=['json', 'csv'], default=None,
                        help='Format to save results (json or csv)')
    parser.add_argument('--silent', action='store_true',
                        help='Suppress output (silent mode)')

def get_parser():
    parser = argparse.ArgumentParser(
        prog='redroom',
        description='RedRoom: All-in-one Hacking Toolkit'
    )

    # Top-level subparser for category
    subparsers = parser.add_subparsers(dest='category', required=True, help='Tool category')

    # ------------------- RECON -------------------
    recon_parser = subparsers.add_parser('recon', help='Reconnaissance tools')
    recon_subparsers = recon_parser.add_subparsers(dest='tool', required=True, help='Recon tool')

    hostscan = recon_subparsers.add_parser('hostscan', help='Perform host discovery')
    hostscan.add_argument('-r', '--range', required=True, help='Target IP or CIDR range')
    hostscan.add_argument('-m', '--method', choices=['arp', 'tcp', 'icmp','udp'], help='Discovery method')
    add_common_args(hostscan)

    hostprofile = recon_subparsers.add_parser('hostprofile', help='Profile active hosts')
    hostprofile.add_argument('-r', '--range', required=True, help='Target IP or CIDR range')
    add_common_args(hostprofile)

    dnsenum = recon_subparsers.add_parser('dnsenum', help='Enumerate DNS records')
    dnsenum.add_argument('-d', '--domain', required=True, help='Target domain for DNS lookup')
    group = dnsenum.add_mutually_exclusive_group()
    group.add_argument('--min', action='store_true', help='Minimal DNS enumeration (A, AAAA, NS)')
    group.add_argument('--full', action='store_true', help='Full DNS enumeration (A, AAAA, MX, etc.)')
    group.add_argument('-zt', '--zonetransfer', action='store_true', help='Try zone transfer to grab all DNS records')
    group.add_argument('--asn', action='store_true', help='ASN lookup')
    group.add_argument('--whois', action='store_true', help='WHOIS lookup')
    add_common_args(dnsenum)

    subenum = recon_subparsers.add_parser('subenum', help='Perform subdomain enumeration')
    subenum.add_argument('-d', '--domain', required=True, help='Target domain for DNS lookup')
    subenum.add_argument('-m', '--method', choices=['passive', 'brute'], default='passive')
    add_common_args(subenum)

    traceroute = recon_subparsers.add_parser('traceroute', help='Run traceroute to a target')
    traceroute.add_argument('-r', '--range', required=True, help='Target IP or CIDR range')
    traceroute.add_argument('-m', '--method', choices=['tcp', 'udp', 'icmp'], help='Traceroute method')
    add_common_args(traceroute)

    portscan = recon_subparsers.add_parser('portscan', help='Run a portscan to a target')
    portscan.add_argument('-r', '--range', required=True, help='Target IP or CIDR range')
    portscan.add_argument('-m', '--method', choices=['tcp', 'udp', 'icmp'], help='Portscan method')
    add_common_args(portscan)

    # ------------------- ANALYSIS -------------------
    analysis_parser = subparsers.add_parser('analysis', help='Analysis tools')
    analysis_subparsers = analysis_parser.add_subparsers(dest='tool', required=True, help='Analysis tool')

    cvelookup = analysis_subparsers.add_parser('cvelookup', help='Perform CVE lookup on target(s)')
    cvelookup.add_argument('-r', '--range', required=True, help='Target IP or CIDR range')
    cvelookup.add_argument('-m', '--method', choices=['tcp', 'udp'], default='tcp',
                           help='Portscan method used internally')
    add_common_args(cvelookup)

    webscanner = analysis_subparsers.add_parser('webscanner', help='Perform a web application scan')
    webscanner.add_argument('-u', '--url', required=True, help='Target URL for web scanning')
    webscanner.add_argument(
        '-m', '--method',
        choices=['wcrawl', 'form', 'sqlfuzz', 'techd', 'all'],
        default='all',
        help='Which part of the web scanner to run (default: all)'
    )
    webscanner.add_argument(
        '-F', '--file', type=str, default=None,
        help='Optional input file (only used by "form" or "sqlfuzz" methods)'
    )
    add_common_args(webscanner)

    misconfdetector = analysis_subparsers.add_parser('mcdetect', help='Perform a misconfig detection scan')
    misconfdetector.add_argument('-r', '--range', required=True, help='Target IP')
    add_common_args(misconfdetector)

    # ------------------- EXPLOIT -------------------

    exploit_parser = subparsers.add_parser('exploit', help='Exploit tools')
    exploit_subparsers = exploit_parser.add_subparsers(dest='tool', required=True, help='Exploit tool')
    maestro = exploit_subparsers.add_parser('Maestro', help='Perform CVE lookup on target(s)')
    
    return parser

def parse_args():
    parser = get_parser()
    args, unknown = parser.parse_known_args()
    args.extra = unknown
    return args