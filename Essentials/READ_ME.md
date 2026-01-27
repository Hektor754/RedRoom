# ---------------------------
# RECON: hostscan
# ---------------------------
python -m main -c recon -t hostscan -r <IP_or_CIDR>
python -m main -c recon -t hostscan -r <IP_or_CIDR> -m arp
python -m main -c recon -t hostscan -r <IP_or_CIDR> -m tcp
python -m main -c recon -t hostscan -r <IP_or_CIDR> -m icmp
python -m main -c recon -t hostscan -r <IP_or_CIDR> -m tcp --timeout 5 --retries 2
python -m main -c recon -t hostscan -r <IP/CIDR> -m tcp --output results.json --format json
python -m main -c recon -t hostscan -r <IP> -m tcp --stealth
python -m main -c recon -t hostscan -r <IP> -m tcp --fin
python -m main -c recon -t hostscan -r <IP> -m tcp --ack
python -m main -c recon -t hostscan -r <IP> -m tcp --xmas
python -m main -c recon -t hostscan -r <IP> -m tcp --syn
python -m main -c recon -t hostscan -r <IP> -m tcp --port 22,80,443
python -m main -c recon -t hostscan -r <IP> -m tcp --silent

# ---------------------------
# RECON: hostprofile
# ---------------------------
python -m main -c recon -t hostprofile -r <IP_or_CIDR>
python -m main -c recon -t hostprofile -r <IP_or_CIDR> --timeout 10 --retries 3
python -m main -c recon -t hostprofile -r <IP> --output hostprofile.json --format json
python -m main -c recon -t hostprofile -r <IP> --silent

# ---------------------------
# RECON: dnsenum
# ---------------------------
python -m main -c recon -t dnsenum -d <domain>
python -m main -c recon -t dnsenum -d <domain> --min
python -m main -c recon -t dnsenum -d <domain> --full
python -m main -c recon -t dnsenum -d <domain> --asn
python -m main -c recon -t dnsenum -d <domain> --whois
python -m main -c recon -t dnsenum -d <domain> --zonetransfer
python -m main -c recon -t dnsenum -d <domain> --timeout 8 --retries 2 --output dns.json

# ---------------------------
# RECON: subenum
# ---------------------------
python -m main -c recon -t subenum -d <domain> -m passive
python -m main -c recon -t subenum -d <domain> -m brute
python -m main -c recon -t subenum -d <domain> -m brute --securitytrails-key <key>
python -m main -c recon -t subenum -d <domain> -m brute --virustotal-key <key>
python -m main -c recon -t subenum -d <domain> -m brute --certspotter-key <key>
python -m main -c recon -t subenum -d <domain> -m brute --alienvault-key <key>
python -m main -c recon -t subenum -d <domain> --output subdomains.csv --format csv

# ---------------------------
# RECON: traceroute
# ---------------------------
python -m main -c recon -t traceroute -r <IP_or_Host>
python -m main -c recon -t traceroute -r <IP> -m tcp
python -m main -c recon -t traceroute -r <IP> -m udp
python -m main -c recon -t traceroute -r <IP> -m icmp
python -m main -c recon -t traceroute -r <IP> --timeout 5 --output trace.json

# ---------------------------
# RECON: portscan
# ---------------------------
python -m main -c recon -t portscan -r <IP_or_range> -m tcp
python -m main -c recon -t portscan -r <IP_or_range> -m udp
python -m main -c recon -t portscan -r <IP_or_range> -m icmp
python -m main -c recon -t portscan -r <IP> -m tcp --port 1-1024
python -m main -c recon -t portscan -r <IP> -m tcp --aggressive
python -m main -c recon -t portscan -r <IP> -m tcp --stealth --port 22,80,443 --output ports.json

# ---------------------------
# ANALYSIS: cvelookup
# ---------------------------
python -m main -c analysis -t cvelookup -r <IP_or_CIDR>
python -m main -c analysis -t cvelookup -r <IP> -m tcp
python -m main -c analysis -t cvelookup -r <IP> -m udp
python -m main -c analysis -t cvelookup -r <IP> --timeout 6 --retries 2 --output cve.json

# ---------------------------
# ANALYSIS: webscanner
# ---------------------------
python -m main -c analysis -t webscanner -u <url>
python -m main -c analysis -t webscanner -u <url> -m wcrawl
python -m main -c analysis -t webscanner -u <url> -m form
python -m main -c analysis -t webscanner -u <url> -m sqlfuzz
python -m main -c analysis -t webscanner -u <url> -m techd
python -m main -c analysis -t webscanner -u <url> -m all
python -m main -c analysis -t webscanner -u <url> -F <input_file>
python -m main -c analysis -t webscanner -u <url> -m sqlfuzz -F subdomains.json --output web_fuzz.json
python -m main -c analysis -t webscanner -u <url> -m form --timeout 10 --retries 1 --output forms.json

# ---------------------------
# ANALYSIS: misconfig / config_checker (URL mode)
# ---------------------------
python -m main -c analysis -t misconfig_checker -u https://example.com
python -m main -c analysis -t misconfig_checker -u https://example.com --checks all --timeout 8 --retries 2
python -m main -c analysis -t misconfig_checker -u https://example.com --checks tls,cors,dir-listing --output misconfig_results.json --format json
python -m main -c analysis -t misconfig_checker -u https://example.com --silent

# ---------------------------
# ANALYSIS: misconfig / config_checker (host/IP mode)
# ---------------------------
python -m main -c analysis -t misconfig_checker -r 192.168.1.5
python -m main -c analysis -t misconfig_checker -r 192.168.1.0/24 --checks tls,cors --output misconfig_scan.csv --format csv
python -m main -c analysis -t misconfig_checker -r 192.168.1.5 --timeout 6 --retries 1

# ---------------------------
# Shared / common examples & flags
# ---------------------------
python -m main -c recon -t hostscan -r <IP> -m tcp --output out.json --format json
python -m main -c recon -t hostscan -r <IP> -m tcp --silent
python -m main -c recon -t subenum -d <domain> -m passive --output subs.json
python -m main -c analysis -t webscanner -u https://example.com -m sqlfuzz -F payloads.txt --output sql_results.json

# ---------------------------
# Examples showing extra TCP flags usage
# ---------------------------
python -m main -c recon -t portscan -r 192.168.1.0/24 -m tcp --stealth --port 1-1024 --output ports.json
python -m main -c recon -t portscan -r 10.0.0.1 -m tcp --syn --port 80,443,22
python -m main -c recon -t hostscan -r 10.0.0.5 -m tcp --fin --port 22

# ---------------------------
# Special/edge commands
# ---------------------------
# Zonetransfer attempt (dnsenum)
python -m main -c recon -t dnsenum -d example.com --zonetransfer

# Subenum brute force with API keys (example)
python -m main -c recon -t subenum -d example.com -m brute --securitytrails-key ABC123 --virustotal-key XYZ456

# Webscanner using forms file
python -m main -c analysis -t webscanner -u https://testlab.local -m form -F forms_export.json --output forms_scan.json
