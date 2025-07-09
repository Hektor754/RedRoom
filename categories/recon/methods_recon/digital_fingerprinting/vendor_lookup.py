from scapy.all import ARP, Ether, srp

def load_oui(filename):
    oui_map = {}
    with open(filename, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            if "(hex)" in line:
                parts = line.strip().split()
                if len(parts) >= 3:
                    key = parts[0].replace("-", ":").lower()
                    vendor = " ".join(parts[2:])
                    oui_map[key] = vendor
    return oui_map      

def lookup_vendor(mac, oui_map):
    if not mac:
        return "Unknown"
    
    mac_prefix = mac.lower()[0:8]
    return oui_map.get(mac_prefix, "Unknown")   