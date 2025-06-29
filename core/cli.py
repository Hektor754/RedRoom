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

    parser.add_argument('-c', '--category', required=True, choices=['recon'],
                        help='Tool category (e.g., recon)')

    subparsers = parser.add_subparsers(dest='tool', required=True,
                                       help='Tool name within category')

    # ─── Hostscan ─────────────────────────────────────────
    hostscan = subparsers.add_parser('hostscan', help='Perform host discovery')
    hostscan.add_argument('-r', '--range', required=True,
                          help='Target IP or CIDR range')
    hostscan.add_argument('-m', '--method', choices=['arp', 'tcp', 'icmp'],
                          help='Discovery method')
    add_common_args(hostscan)

    # ─── Hostprofile ─────────────────────────────────────
    hostprofile = subparsers.add_parser('hostprofile', help='Profile active hosts')
    hostprofile.add_argument('-r', '--range', required=True,
                             help='Target IP or CIDR range')
    add_common_args(hostprofile)

    # ─── DNS Enumeration ─────────────────────────────────
    dnsenum = subparsers.add_parser('dnsenum', help='Enumerate DNS records')
    dnsenum.add_argument('-d', '--domain', required=True,
                         help='Target domain for DNS lookup')
    group = dnsenum.add_mutually_exclusive_group()
    group.add_argument('--min', action='store_true',
                       help='Minimal DNS enumeration (A, AAAA, NS)')
    group.add_argument('--full', action='store_true',
                       help='Full DNS enumeration (A, AAAA, MX, etc.)')
    add_common_args(dnsenum)

    # ─── Traceroute ──────────────────────────────────────
    traceroute = subparsers.add_parser('traceroute', help='Run traceroute to a target')
    traceroute.add_argument('-r', '--range', required=True,
                            help='Target IP or CIDR range')
    traceroute.add_argument('-m', '--method', choices=['tcp', 'udp', 'icmp'],
                            help='Traceroute method')
    add_common_args(traceroute)

    return parser


def parse_args():
    parser = get_parser()
    args, unknown = parser.parse_known_args()
    args.extra = unknown
    return args