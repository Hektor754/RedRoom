import argparse

def parse_args():
    parser = argparse.ArgumentParser(
        prog='redroom',
        description='RedRoom: All-in-one Hacking Toolkit'
    )

    parser.add_argument(
        '-c','--category',
        required=True,
        choices=['recon'],
        help='Tool category (e.g., recon)'
    )

    parser.add_argument(
        '-t', '--tool',
        required=True,
        choices=['hostscan'],
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
        required=True,
        help='Tool target IP or IP range (CIDR notation supported)'
    )

    args, unknown = parser.parse_known_args()
    args.extra = unknown
    return args
