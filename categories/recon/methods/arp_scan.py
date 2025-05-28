from scapy.all import ARP, Ether, srp

def arp_scan(args):
    target_ip = args.range

    arp_request = ARP(pdst=target_ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request

    answered_list = srp(arp_request_broadcast, timeout = 2, verbose=False)[0]

    results = []
    for sent, received in answered_list:
        results.append({'ip':received.psrc, 'mac': received.hwsrc})

    for host in results:
        print(f"IP: {host['ip']}  MAC: {host['mac']}")

    return results       