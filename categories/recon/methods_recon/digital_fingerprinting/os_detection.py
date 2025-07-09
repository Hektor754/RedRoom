from scapy.all import TCP, ICMP, IP, send, sr1
import concurrent.futures
import time
from collections import Counter
import logging
from datetime import datetime

class OSDetector:
    def __init__(self):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("OSDetector")

        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 
            3389, 8080, 8443
        ]

        self.candidates_window = []
        self.candidates_ttl = []
        self.os_mapping = {
            32: ["Windows 95/98/ME"],
            64: ["Linux", "macOS", "FreeBSD", "Unix variants"],
            128: ["Windows NT/2000/XP/7/8/10/11"],
            255: ["Cisco devices", "Network equipment"],
            0: ["Unknown"]
        }
        
        self.os_signatures = {
            65535: ["Windows 10/11", "Windows Server 2016+", "macOS (recent)"],
            8192: ["Windows 7/8", "Windows Server 2008/2012"],
            16384: ["Windows Vista"],
            64240: ["Windows (some configurations)"],
            5840: ["Linux (Ubuntu/Debian)"],
            5792: ["Linux (CentOS/RHEL)"],
            29200: ["Linux (recent kernels)"],
            32768: ["macOS (older)", "iOS"],
            4128: ["Cisco IOS"],
            5720: ["JunOS"],
            0: ["Unknown"]
        }

    def send_syn(self, target_ip, target_port):
        try:
            syn_packet = IP(dst=target_ip)/TCP(
                dport=target_port,
                flags="S",
                options=[('MSS', 1460)]
            )

            response = sr1(syn_packet, timeout=2, verbose=0)
            
            if response and response.haslayer(TCP):
                if response[TCP].flags == 0x12:
                    window_size = response[TCP].window

                    rst_packet = IP(dst=target_ip)/TCP(
                        dport=target_port,
                        sport=response[TCP].dport,
                        flags="R",
                        seq=response[TCP].ack
                    )
                    send(rst_packet, verbose=0)
                    return target_port, window_size
            
            return target_port, None
            
        except Exception as e:
            self.logger.debug(f"Port {target_port} scan failed: {str(e)}")
            return target_port, None

    def send_echo_pings(self, target_ip):
        responses = []
        try:
            for pkt in [
                IP(dst=target_ip)/ICMP(),
                IP(dst=target_ip)/TCP(dport=80, flags="S")
            ]:
                responses.append(sr1(pkt, timeout=2, verbose=0))
                time.sleep(1)

            ttls = [
                r[IP].ttl for r in responses 
                if r and IP in r and r[IP].ttl is not None
            ]
            
            return ttls if ttls else None
            
        except Exception as e:
            self.logger.debug(f"Ping failed: {str(e)}")
            return None

    def calculate_original_ttl(self, received_ttl):
        if received_ttl is None:
            self.candidates_ttl.append(0)
            return

        initial_ttls = [32, 64, 128, 255]

        closest = min(initial_ttls, key=lambda x: abs(x - received_ttl))
        self.candidates_ttl.append(closest)

    def analyse_window_size(self, window_size):
        if window_size is None: 
            self.candidates_window.append(0)
            return

        if window_size in self.os_signatures:
            self.candidates_window.append(window_size)
            return

        for scale in [1, 2, 4, 8]:
            scaled = window_size * scale
            for known_size in self.os_signatures:
                if abs(scaled - known_size) <= 10:
                    self.candidates_window.append(known_size)
                    return

        self.candidates_window.append(0)

    def scan_multiple_ports(self, target_ip, max_threads=50):
        def task(port):
            _, window_size = self.send_syn(target_ip, port)
            self.analyse_window_size(window_size)
            return window_size

        with concurrent.futures.ThreadPoolExecutor(
            max_workers=min(max_threads, len(self.common_ports))
        ) as executor:
            futures = [executor.submit(task, port) for port in self.common_ports]
            concurrent.futures.wait(futures)

    def scan_ttl_probes(self, target_ip, rounds=3):
        for _ in range(rounds):
            ttls = self.send_echo_pings(target_ip)
            if ttls:
                for ttl in ttls:
                    self.calculate_original_ttl(ttl)
            time.sleep(1)

    def find_best_guess(self):
        window_counter = Counter(self.candidates_window)
        ttl_counter = Counter(self.candidates_ttl)
        
        most_common_window = window_counter.most_common(1)[0][0] if window_counter else 0
        most_common_ttl = ttl_counter.most_common(1)[0][0] if ttl_counter else 0
        
        window_os = self.os_signatures.get(most_common_window, ["Unknown"])
        ttl_os = self.os_mapping.get(most_common_ttl, ["Unknown"])
        
        window_confidence = window_counter[most_common_window] / sum(window_counter.values()) if window_counter else 0
        ttl_confidence = ttl_counter[most_common_ttl] / sum(ttl_counter.values()) if ttl_counter else 0
        
        combined_confidence = (window_confidence * 0.7) + (ttl_confidence * 0.3)
        
        common_guesses = list(set(window_os) & set(ttl_os))
        if not common_guesses:
            common_guesses = window_os + ttl_os
        
        return {
            "window_data": {
                "value": most_common_window,
                "count": window_counter.get(most_common_window, 0),
                "possible_os": window_os,
                "confidence": window_confidence
            },
            "ttl_data": {
                "value": most_common_ttl,
                "count": ttl_counter.get(most_common_ttl, 0),
                "possible_os": ttl_os,
                "confidence": ttl_confidence
            },
            "combined_confidence": combined_confidence,
            "os_guesses": common_guesses
        }

    def run(self, target_ip):
        self.logger.info(f"Starting OS detection for {target_ip}")
        
        self.candidates_window = []
        self.candidates_ttl = []
        
        try:
            start_time = time.time()
            
            self.logger.info("Starting port scan phase...")
            self.scan_multiple_ports(target_ip)
            
            self.logger.info("Starting TTL probe phase...")
            self.scan_ttl_probes(target_ip)
            
            results = self.find_best_guess()
            duration = time.time() - start_time

            combined_confidence = results.get("combined_confidence", 0)
            if combined_confidence > 0.7:
                confidence_str = "high"
            elif combined_confidence > 0.4:
                confidence_str = "medium"
            else:
                confidence_str = "low"

            os_guesses = results.get("os_guesses", [])
            primary_guess = os_guesses[0] if os_guesses else "Unknown"
            alternatives = os_guesses[1:] if len(os_guesses) > 1 else []

            report = {
                "primary_guess": primary_guess,
                "confidence": confidence_str,
                "alternatives": alternatives,
                "window_size": results["window_data"]["value"],
                "ttl": results["ttl_data"]["value"],
                "duration_seconds": round(duration, 2),
                "scanned_ports": len(self.common_ports)
            }
            
            self.logger.info(f"Scan completed in {duration:.2f} seconds")
            return report
            
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            return {
                "error": str(e),
                "target": target_ip,
                "status": "failed"
            }