import re
import json

class CVE_Scan:
    @staticmethod
    def scan_handler(portscan_results):
        if not portscan_results:
            print("[!] No portscan results provided.")
            return

        formatted_results = CVE_Scan.format_for_cve_lookup(portscan_results)
        if not formatted_results:
            print("[!] No valid services found to match against CVEs.")
            return

        raw_cve_db = CVE_Scan.load_cve_database("nvdcve-1.1-recent.json")
        cve_database = CVE_Scan.parse_nvd_cve_data(raw_cve_db)
        if not cve_database:
            print("[!] No CVE entries loaded from database.")
            return

        matches = CVE_Scan.find_matches(cve_database, formatted_results)

        if not matches:
            print("[+] No CVEs matched the scanned services.")
            return

        return matches

    @staticmethod
    def find_matches(cve_db, formatted_results):
        def normalize(text):
            return re.sub(r'[^a-z0-9]', '', text.lower())

        def is_relevant_cve(cve_desc, service_name):
            """
            Filter out obviously irrelevant CVEs but be less restrictive
            """
            desc_lower = cve_desc.lower()
            service_lower = service_name.lower()
            
            # Skip only very obvious kernel CVEs for network services
            if 'linux kernel' in desc_lower and any(net in service_lower for net in ['http', 'https', 'apache', 'nginx']):
                return False
            
            # Skip obvious hardware CVEs for software services
            if any(hw in desc_lower for hw in ['firmware', 'bios', 'router']) and any(sw in service_lower for sw in ['http', 'ssh', 'ftp']):
                return False
            
            return True

        def version_compare(detected_version, cve_version):
            """
            Balanced version comparison logic
            """
            # If no detected version, skip version-specific CVEs
            if not detected_version:
                return not cve_version  # Only match if CVE also has no version
            
            # If CVE has no version, it's a general product vulnerability
            if not cve_version:
                return True
            
            # Normalize versions
            det_ver = detected_version.lower().lstrip('v').strip()
            cve_ver = cve_version.lower().lstrip('v').strip()
            
            # Skip if versions are too short or generic
            if len(det_ver) < 2 or len(cve_ver) < 2:
                return True  # Allow matching for generic versions
            
            # Exact match
            if det_ver == cve_ver:
                return True
            
            # Version range matching (e.g., 2.4.41 matches 2.4)
            if det_ver.startswith(cve_ver + '.') or cve_ver.startswith(det_ver + '.'):
                return True
            
            # Major version matching for cases like 2.4.x
            try:
                det_parts = det_ver.split('.')
                cve_parts = cve_ver.split('.')
                
                # If CVE version is shorter, check if it's a major version match
                if len(cve_parts) < len(det_parts):
                    if det_ver.startswith(cve_ver):
                        return True
                
                # Major.minor matching
                if len(det_parts) >= 2 and len(cve_parts) >= 2:
                    if det_parts[0] == cve_parts[0] and det_parts[1] == cve_parts[1]:
                        return True
            except:
                pass
            
            return False

        matches = []

        for entry in formatted_results:
            ip = entry["ip"]
            port = entry["port"]
            service_name = entry["service_name"]
            version = entry["version"].strip()

            # Skip if no proper service name or version
            if not service_name or len(service_name) < 3:
                continue

            norm_service = normalize(service_name)

            for cve in cve_db:
                cve_product = cve["product"]
                cve_version = cve["version"]
                cve_desc = cve.get("description", "")

                # Skip rejected/withdrawn CVEs
                if "rejected" in cve_desc.lower() or "withdrawn" in cve_desc.lower():
                    continue

                # Filter out obviously irrelevant CVEs but be less strict
                if not is_relevant_cve(cve_desc, service_name):
                    continue

                norm_product = normalize(cve_product)

                # Matching logic with debugging
                service_match = False
                match_type = ""
                
                # Exact product name match
                if norm_service == norm_product:
                    service_match = True
                    match_type = "exact"
                
                # Check service variants
                elif CVE_Scan.is_service_variant(service_name, cve_product):
                    service_match = True
                    match_type = "variant"
                
                # Less strict substring matching for common cases
                elif (len(norm_service) > 3 and len(norm_product) > 3 and 
                      (norm_service in norm_product or norm_product in norm_service)):
                    # Only allow if the match is meaningful (not too generic)
                    if not any(generic in norm_service for generic in ['http', 'server', 'service']):
                        service_match = True
                        match_type = "substring"

                if service_match:
                    if version_compare(version, cve_version):
                        print(f"[DEBUG] MATCH: {service_name} v{version} -> {cve_product} v{cve_version} ({match_type})")
                        matches.append({
                            "ip": ip,
                            "port": port,
                            "service_name": service_name,
                            "version": version,
                            "cve_id": cve["cve_id"],
                            "description": cve["description"],
                            "cve_product": cve_product,
                            "cve_version": cve_version,
                            "match_type": match_type
                        })

        return matches

    @staticmethod
    def is_service_variant(service_name, cve_product):
        """
        Check for common service name variations - much stricter
        """
        service_variants = {
            'apache': ['httpd', 'apache_http_server'],
            'nginx': ['nginx_http_server'],
            'openssh': ['ssh'],
            'mysql': ['mysql_server'],
            'postgresql': ['postgres'],
            'vsftpd': ['ftp'],
            'proftpd': ['ftp'],
            'bind': ['named', 'bind9'],
            'postfix': ['postfix'],
            'dovecot': ['dovecot'],
            'samba': ['smb']
        }
        
        service_lower = service_name.lower()
        product_lower = cve_product.lower()
        
        # Only match if there's an exact variant relationship
        for main_service, variants in service_variants.items():
            if service_lower == main_service and product_lower in variants:
                return True
            if product_lower == main_service and service_lower in variants:
                return True
            if service_lower in variants and product_lower == main_service:
                return True
        
        return False

    @staticmethod
    def format_for_cve_lookup(portscan_results):
        cve_targets = []
        for scan_type, entries in portscan_results.items():
            for entry in entries:
                ip = entry['ip']
                services = entry.get('services', [])
                for service in services:
                    port = service.get('port')
                    banner = service.get('banner', '')
                    name, version = CVE_Scan.parse_service(banner)
                    if name:
                        cve_targets.append({
                            "ip": ip,
                            "port": port,
                            "service_name": name,
                            "version": version or ""
                        })
        return cve_targets

    @staticmethod
    def parse_service(service_str):
        """
        Improved service parsing with better regex patterns
        """
        if not service_str:
            return "", None
        
        # Clean the input
        service_str = service_str.strip()
        
        # Common service banner patterns
        patterns = [
            # Apache/2.4.41 (Ubuntu)
            r'([A-Za-z]+)/(\d+(?:\.\d+)*(?:\.\d+)*)',
            # OpenSSH_7.4p1
            r'([A-Za-z]+)_(\d+(?:\.\d+)*(?:[a-z]\d+)?)',
            # nginx/1.18.0
            r'([A-Za-z]+)/(\d+(?:\.\d+)*)',
            # Microsoft-IIS/10.0
            r'([A-Za-z\-]+)/(\d+(?:\.\d+)*)',
            # MySQL 5.7.32-0ubuntu0.18.04.1
            r'([A-Za-z]+)\s+(\d+(?:\.\d+)*(?:\.\d+)*)',
            # vsftpd 3.0.3
            r'([A-Za-z]+)\s+(\d+(?:\.\d+)*)',
            # Postfix 3.4.13
            r'([A-Za-z]+)\s+(\d+(?:\.\d+)*)',
            # Pure-FTPd 1.0.49
            r'([A-Za-z\-]+)\s+(\d+(?:\.\d+)*)',
            # ProFTPD 1.3.6
            r'([A-Za-z]+)\s+(\d+(?:\.\d+)*)',
            # Dovecot ready (version 2.3.7.2)
            r'([A-Za-z]+).*version\s+(\d+(?:\.\d+)*)',
            # Version at the end: Service 2.4.41
            r'([A-Za-z]+).*?(\d+(?:\.\d+){1,3})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, service_str, re.IGNORECASE)
            if match:
                name = match.group(1).strip()
                version = match.group(2).strip()
                # Filter out obviously wrong extractions
                if len(name) >= 2 and not name.isdigit():
                    return name, version
        
        # If no version found, try to extract service name only
        name_patterns = [
            r'^([A-Za-z][A-Za-z0-9_\-]*)',  # Service name at the beginning
            r'([A-Za-z]{3,})',  # Any alphabetic word with 3+ chars
        ]
        
        for pattern in name_patterns:
            match = re.search(pattern, service_str)
            if match:
                name = match.group(1).strip()
                if len(name) >= 3 and not name.isdigit():
                    return name, None
        
        return service_str.strip(), None

    @staticmethod
    def load_cve_database(filepath):
        try:
            with open(filepath, 'r', encoding='utf-8') as file:
                data = json.load(file)
            return data
        except Exception as e:
            print(f"[!] Failed to load CVE database: {e}")
            return {}

    @staticmethod
    def parse_nvd_cve_data(raw_data):
        def extract_cpes(nodes):
            products = []
            versions = []
            for node in nodes:
                for cpe in node.get("cpe_match", []):
                    uri = cpe.get("cpe23Uri", "")
                    parts = uri.split(":")
                    if len(parts) > 5:
                        product = parts[4]
                        version = parts[5]
                        # Add entries with valid products (version can be empty)
                        if product and product not in ["*", "-", ""]:
                            products.append(product)
                            # Allow empty versions but normalize wildcards
                            if version and version not in ["*", "-"]:
                                versions.append(version)
                            else:
                                versions.append("")  # Empty version
                if "children" in node:
                    child_products, child_versions = extract_cpes(node["children"])
                    products.extend(child_products)
                    versions.extend(child_versions)
            return products, versions

        cves = []
        seen = set()
        items = raw_data.get("CVE_Items", [])

        for item in items:
            cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID", "")
            descriptions = item.get("cve", {}).get("description", {}).get("description_data", [])
            description = descriptions[0]["value"] if descriptions else ""

            # Skip if no CVE ID or description
            if not cve_id or not description:
                continue

            nodes = item.get("configurations", {}).get("nodes", [])
            products, versions = extract_cpes(nodes)

            # Add CVEs with valid products (version optional)
            if products:
                for p, v in zip(products, versions):
                    # Only require meaningful product names
                    if p and len(p) > 2:
                        key = (cve_id, p, v)
                        if key not in seen:
                            seen.add(key)
                            cves.append({
                                "cve_id": cve_id,
                                "description": description,
                                "product": p,
                                "version": v or ""  # Empty string if no version
                            })

        print(f"[+] Loaded {len(cves)} CVE entries from database (filtered)")
        return cves