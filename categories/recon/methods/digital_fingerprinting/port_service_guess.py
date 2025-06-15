import socket
from concurrent.futures import ThreadPoolExecutor

COMMON_PORTS = {
    20: "FTP (Data)",
    21: "FTP (Control)",
    22: "SSH / SFTP",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP (Server)",
    68: "DHCP (Client)",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPCbind / portmapper",
    119: "NNTP",
    123: "NTP",
    135: "Microsoft RPC",
    137: "NetBIOS Name Service",
    138: "NetBIOS Datagram",
    139: "NetBIOS Session",
    143: "IMAP",
    161: "SNMP",
    162: "SNMP Trap",
    179: "BGP",
    194: "IRC",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB / CIFS",
    465: "SMTPS (legacy)",
    514: "Syslog",
    515: "LPD (Printer)",
    520: "RIP",
    587: "SMTP (Submission)",
    631: "IPP (Printing)",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1080: "SOCKS Proxy",
    1433: "MSSQL",
    1434: "MSSQL Monitor",
    1521: "Oracle DB",
    1701: "L2TP",
    1812: "RADIUS (Auth)",
    1813: "RADIUS (Acct)",
    2049: "NFS",
    2082: "cPanel",
    2083: "cPanel (SSL)",
    2100: "Oracle XDB",
    2483: "Oracle DB (TCP)",
    2484: "Oracle DB (SSL)",
    3306: "MySQL",
    3389: "RDP (Remote Desktop)",
    3690: "Subversion",
    4000: "ICQ",
    4444: "Metasploit / Oracle",
    5000: "UPnP / Flask Dev",
    5060: "SIP (VoIP)",
    5432: "PostgreSQL",
    5900: "VNC",
    5985: "WinRM (HTTP)",
    5986: "WinRM (HTTPS)",
    6379: "Redis",
    6667: "IRC",
    8000: "HTTP Alt / Dev",
    8080: "HTTP Proxy / Alt",
    8443: "HTTPS Alt / Admin UI",
    8888: "Web UI / Proxy",
    9000: "PHP-FPM / Dev Tools",
    9200: "Elasticsearch",
    9300: "Elasticsearch Node",
    11211: "Memcached",
    27017: "MongoDB",
    50000: "SAP / Sybase / IBM DB2",
}


def quick_tcp_scan(ip, ports, timeout=3.0, max_workers=50):
    open_ports = []
    services = []

    def scan_port(port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            try:
                s.connect((ip, port))
                return port
            except:
                return None

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = executor.map(scan_port, ports)

    for port in results:
        if port is not None:
            open_ports.append(port)
            services.append(COMMON_PORTS.get(port, "Unknown"))
    return open_ports, services