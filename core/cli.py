import argparse

def parse_args():
    parser = argparse.ArgumentParser(
        prog='redroom',
        description='RedRoom: All-in-one Hacking Toolkit'
    )

    group = parser.add_mutually_exclusive_group()

    parser.add_argument(
        '-c','--category',
        required=True,
        choices=['recon'],
        help='Tool category (e.g., recon)'
    )

    parser.add_argument(
        '-t', '--tool',
        required=True,
        choices=['hostscan','hostprofile','dnsenum','traceroute'],
        help='Tool name within category (e.g., hostscan)'
    )

    parser.add_argument(
        '-m','--method',
        required=False,
        choices=['arp', 'tcp','icmp'],
        help='Method used by the tool (e.g., icmp, arp, tcp)'
    )

    parser.add_argument(
        '-r','--range',
        required=False,
        help='Tool target IP or IP range (CIDR notation supported)'
    )

    parser.add_argument(
        '-d','--domain',
        required=False,
        help='Tool target domain'
    )

    parser.add_argument(
        '--timeout',
        type=float,
        default=2.0,
        required=False,
        help='Timeout in seconds to wait for each probe (default: 1.0)'
    )

    parser.add_argument(
        '--retries',
        type=int,
        default=2,
        required=False,
        help='Number of retries if no response (default: 1)'
    )

    group.add_argument(
        '--min',
        action='store_true',
        help='Minimal DNS enumeration (A, AAAA, NS)'
    )

    group.add_argument(
        '--full',
        action='store_true',
        help='Full DNS enumeration (A, AAAA, MX, NS, CNAME, TXT, SOA, SRV, AXFR)'
    )

    parser.add_argument(
        '--output',
        type=str,
        default=None,
        help='Output to save results on a file'
    )

    parser.add_argument(
        '--format',
        choices=['json','csv'],
        type=str,
        default=None,
        help='format to save results on a file'
    )

    parser.add_argument(
        '--silent',
        action='store_true',
        help='handles the verbose'
    )

    args, unknown = parser.parse_known_args()
    args.extra = unknown
    return args
