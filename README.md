# RedRoom Toolkit - CLI Usage Documentation

## 🔰 Syntax
```
sudo python3 -m main -c <category> -t <tool> [OPTIONS]
```

---

## 📂 Categories (`-c`)

- `recon` — Reconnaissance tools
- `analysis` — Analysis tools

---

## 🔧 Tools per Category (`-t`)

### recon
- `hostscan` — Perform host discovery
- `hostprofile` — Profile discovered hosts
- `dnsenum` — Enumerate DNS records
- `subenum` — Subdomain enumeration
- `traceroute` — Network path tracing
- `portscan` — Scan open ports

### analysis
- `cvelookup` — Perform CVE lookups on known services

---

## ✅ Valid Options by Tool

### 🧭 `recon hostscan`
```
-c recon -t hostscan -r <IP/CIDR>
-m [arp | tcp | icmp]
--timeout <float>
--retries <int>
--output <file>
--format [json | csv]
--silent
# TCP Flags (via extra):
--stealth | --fin | --ack | --xmas | --syn | --port
```

---

### 🧬 `recon hostprofile`
```
-c recon -t hostprofile -r <IP/CIDR>
--timeout <float>
--retries <int>
--output <file>
--format [json | csv]
--silent
# No -m/--method allowed
```

---

### 🌐 `recon dnsenum`
```
-c recon -t dnsenum -d <domain>
--min
--full
--asn
--whois
-zt | --zonetransfer
--timeout <float>
--retries <int>
--output <file>
--format [json | csv]
--silent
```

---

### 🌍 `recon subenum`
```
-c recon -t subenum -d <domain>
-m [passive | brute]
--securitytrails-key <key>
--virustotal-key <key>
--certspotter-key <key>
--alienvault-key <key>
--timeout <float>
--retries <int>
--output <file>
--format [json | csv]
--silent
```

---

### 🛰️ `recon traceroute`
```
-c recon -t traceroute -r <IP/CIDR>
-m [tcp | udp | icmp]
--timeout <float>
--retries <int>
--output <file>
--format [json | csv]
--silent
```

---

### 🔎 `recon portscan`
```
-c recon -t portscan -r <IP/CIDR>
-m [tcp | udp | icmp]
--timeout <float>
--retries <int>
--output <file>
--format [json | csv]
--silent
# TCP Flags (via extra):
--stealth | --fin | --ack | --xmas | --syn | --port | --aggressive
```

---

### 🧠 `analysis cvelookup`
```
-c analysis -t cvelookup -r <IP/CIDR>
-m [tcp | udp]   (default: tcp)
--timeout <float>
--retries <int>
--output <file>
--format [json | csv]
--silent
```

---

## 🌐 `web scanner`
```
-c analysis -t webscanner -u <url>
-m [wcrawl | form | sqlfuzz | techd | all]
-F <input_file>            # Optional, used only for 'form' or 'sqlfuzz' methods
--timeout <float>
--retries <int>
--output <file>
--format [json | csv]
--silent
```

---

## ⚙️ TCP Scan Flags (via `extra` args)
Applies to `hostscan`, `portscan`, `hostprofile`, and `cvelookup`:
```
--stealth      or -s     # SYN scan
--fin          or -f
--ack          or -a
--xmas         or -x
--syn          or -Sn
--aggressive   or -A
--port         or -p     # Comma-separated: "80,443,22"
```

---

## 🚫 Invalid Usage (Examples)

| ❌ Command | 💥 Error |
|-----------|----------|
| `-c recon -t hostprofile -m tcp` | `hostprofile` does **not** accept `-m` |
| `--aggressive` not defined in some flags | `'Namespace' object has no attribute 'aggressive'` |
| `--port 70000` | Port out of range |
| `--format xml` | Only `json` or `csv` allowed |
| Conflicting DNS flags (e.g., `--min` + `--asn`) | Mutually exclusive error |
| Missing required flag like `-r` or `-d` | Argparse throws required argument error |

---

## 🛠 Recommendations

- Unify TCP flag parsers to avoid inconsistent attributes.
- Set default values for flags like `aggressive` to prevent runtime errors.
- Validate unknown `extra` args and warn the user.
- Consider showing `--help` if unknown or conflicting flags are passed.

---
