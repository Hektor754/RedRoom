from scapy.all import TCP, UDP, ICMP, IP, send, sr1
import time
from collections import Counter

class OSDetector:
    def __init__(self):
        self.canditates1 = []
        self.canditates2 = []
        self.os_mapping = {
            64: ["Linux", "macOS", "FreeBSD", "Unix variants"],
            128: ["Windows (all versions)", "Windows Server"],
            255: ["Cisco devices", "Network equipment", "Some Unix systems"],
            0: ["Unknown - no reliable TTL data"]
        }
        self.os_signatures = {
            65535: ["Windows 10/11", "Windows Server 2016+", "macOS (some versions)", "iOS"],
            8192: ["Windows 7/8", "Windows Server 2008/2012"],
            16384: ["Windows Vista", "Some Windows variants"],
            5840: ["Linux (Ubuntu/Debian)", "Some Linux distributions"],
            5792: ["Linux (CentOS/RHEL)", "Some Linux variants"],
            65240: ["Linux (some kernels)", "Android"],
            64240: ["Linux (common)", "Debian/Ubuntu", "Scanme.nmap.org"],
            32768: ["FreeBSD", "Some BSD variants"],
            29200: ["macOS (recent versions)"],
            14600: ["macOS (older versions)"],
            1024: ["Some embedded systems"],
            4096: ["Some routers/embedded devices"],
            1: ["Likely Windows (pattern based)"],
            0: ["Unknown - no reliable window data"]
        }

    def send_syn(self, target_ip, target_port):
        try:
            syn_packet = IP(dst=target_ip) / TCP(dport=target_port, flags="S", seq=1000, sport=12345)
            response = sr1(syn_packet, timeout=3, verbose=0)
            print(f"[DEBUG] SYN Response from {target_ip}:{target_port} -> {response.summary() if response else 'No response'}")

            if response and response.haslayer(TCP) and (response[TCP].flags & 0x12) == 0x12:
                window_size = response[TCP].window
                print(f"[DEBUG] Window size: {window_size}")

                rst_packet = IP(dst=target_ip) / TCP(dport=target_port, sport=12345, flags="R", seq=response[TCP].ack)
                send(rst_packet, verbose=0)
                return window_size
            else:
                print(f"[DEBUG] Ignored non-SYN-ACK response on port {target_port}")
                return None
        except Exception as e:
            print(f"[DEBUG] Exception in send_syn: {e}")
        return None

    def send_echo_pings(self, target_ip):
        ping_packet = IP(dst=target_ip) / ICMP()
        tcp_packet = IP(dst=target_ip) / TCP(dport=80, flags="S")
        udp_packet = IP(dst=target_ip) / UDP(dport=53)

        response_icmp = sr1(ping_packet, timeout=3, verbose=0)
        time.sleep(0.1)
        response_tcp = sr1(tcp_packet, timeout=3, verbose=0)
        time.sleep(0.1)
        response_udp = sr1(udp_packet, timeout=3, verbose=0)

        ttl_values = []

        if response_icmp and response_icmp.haslayer(IP):
            if response_icmp[IP].ttl is not None:
                ttl_values.append(response_icmp[IP].ttl)

        if response_tcp and response_tcp.haslayer(IP):
            if response_tcp[IP].ttl is not None:
                ttl_values.append(response_tcp[IP].ttl)
            if response_tcp.haslayer(TCP) and response_tcp[TCP].flags == 18:
                rst_packet = IP(dst=target_ip) / TCP(
                    dport=80, sport=response_tcp[TCP].dport,
                    flags="R", seq=response_tcp[TCP].ack
                )
                send(rst_packet, verbose=0)

        if response_udp and response_udp.haslayer(IP):
            if response_udp[IP].ttl is not None:
                ttl_values.append(response_udp[IP].ttl)

        print(f"[DEBUG] TTL values: {ttl_values}")

        if len(ttl_values) == 0:
            return None, "no_response", {}

        max_ttl = max(ttl_values)
        min_ttl = min(ttl_values)
        ttl_diff = max_ttl - min_ttl

        if ttl_diff <= 2:
            confidence = "high_confidence"
            reliable_ttl = max_ttl
        elif ttl_diff <= 10:
            confidence = "medium_confidence"
            reliable_ttl = max_ttl
        elif ttl_diff > 30:
            confidence = "unreliable"
            reliable_ttl = None
        else:
            confidence = "low_confidence"
            reliable_ttl = max_ttl

        return reliable_ttl, confidence, {}

    def analyse_window_size(self, window_size):
        print(f"[DEBUG] Analyzing window size: {window_size}")
        if window_size is None:
            return

        if window_size in self.os_signatures:
            self.canditates1.append(window_size)
            return

        if (window_size % 8192 == 0 or window_size % 65535 == 0) and window_size > 0:
            self.canditates1.append(1)
            return

        for known_size in self.os_signatures.keys():
            if abs(window_size - known_size) < 100:
                self.canditates1.append(known_size)
                return

        self.canditates1.append(0)

    def calculate_original_ttl(self, received_ttl):
        print(f"[DEBUG] Processing received TTL: {received_ttl}")
        if received_ttl is None:
            self.canditates2.append(0)
            return
        if received_ttl <= 64:
            self.canditates2.append(64)
        elif received_ttl <= 128:
            self.canditates2.append(128)
        elif received_ttl <= 255:
            self.canditates2.append(255)
        else:
            self.canditates2.append(0)

    def scan_multiple_ports(self, target_ip, ports=None):
        if ports is None:
            ports = [80, 443, 22, 21, 25, 53, 110, 993, 995]
        for port in ports:
            window_size = self.send_syn(target_ip, port)
            self.analyse_window_size(window_size)
            time.sleep(0.2)

    def scan_ttl_probes(self, target_ip, rounds=3):
        for _ in range(rounds):
            ttl, _, _ = self.send_echo_pings(target_ip)
            self.calculate_original_ttl(ttl)
            time.sleep(0.5)

    def find_best_guess(self):
        window_counter = Counter(self.canditates1)
        ttl_counter = Counter(self.canditates2)

        most_common_window = window_counter.most_common(1)[0] if window_counter else (0, 0)
        most_common_ttl = ttl_counter.most_common(1)[0] if ttl_counter else (0, 0)

        window_os_list = self.os_signatures.get(most_common_window[0], [])
        ttl_os_list = self.os_mapping.get(most_common_ttl[0], [])

        print(f"[DEBUG] Most common window: {most_common_window}")
        print(f"[DEBUG] Most common TTL: {most_common_ttl}")
        print(f"[DEBUG] OS guesses from window: {window_os_list}")
        print(f"[DEBUG] OS guesses from TTL: {ttl_os_list}")

        all_guesses = window_os_list + ttl_os_list
        if not all_guesses:
            return ["Unknown OS"]

        os_count = Counter(all_guesses)
        max_count = os_count.most_common(1)[0][1]
        top_guesses = [os for os, count in os_count.items() if count == max_count]

        return top_guesses

    def run(self, target_ip):
        self.canditates1.clear()
        self.canditates2.clear()

        self.scan_multiple_ports(target_ip)
        self.scan_ttl_probes(target_ip)

        os_guess_list = self.find_best_guess()
        window_counter = Counter(self.canditates1)
        ttl_counter = Counter(self.canditates2)

        window_os = self.os_signatures.get(window_counter.most_common(1)[0][0], []) if window_counter else []
        ttl_os = self.os_mapping.get(ttl_counter.most_common(1)[0][0], []) if ttl_counter else []

        return {
            'window_result': (window_counter.most_common(1)[0][0], window_counter.most_common(1)[0][1], window_os) if window_counter else (0, 0, []),
            'ttl_result': (ttl_counter.most_common(1)[0][0], ttl_counter.most_common(1)[0][1], ttl_os) if ttl_counter else (0, 0, []),
            'overall_confidence': (
                "high" if len(os_guess_list) == 1 else "medium" if len(os_guess_list) < 4 else "low"
            ),
            'common_matches': os_guess_list
        }