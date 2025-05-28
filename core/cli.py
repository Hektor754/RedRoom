import argparse

def parse_args():
    parser = argparse.ArgumentParser(
        prog='killshot',
        description='Killshot: All-in-one Hacking Toolkit'
    )

    parser.add_argument(
        '-c','--category',
        required=True,
        help='Tool category (e.g., recon, exploit, etc.)'
    )

    parser.add_argument(
        '-t', '--tool',
        required=True,
        help='Tool name within category (e.g., hostscan, portscan)'
    )

    parser.add_argument(
        '-m','--method',
        required=False,
        help='Method used by the tool (e.g., icmp, arp, tcp)'
    )

    parser.add_argument(
        '-r','--range',
        required=True,
        help='Tool target IP or IP range'
    )

    args = parser.parse_args()
    return args