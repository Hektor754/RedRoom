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
        matches = []

        for entry in formatted_results:
            ip = entry["ip"]
            port = entry["port"]
            service_name = entry["service_name"]
            version = entry["version"]

            normalized_service = re.sub(r'[^a-z0-9]', '', service_name.lower())

            for cve in cve_db:
                cve_product = cve["product"]
                cve_version = cve["version"]

                normalized_product = re.sub(r'[^a-z0-9]', '', cve_product.lower())

                match_product = normalized_service in normalized_product or normalized_product in normalized_service
                match_version = not cve_version or not version or cve_version == version

                if match_product and match_version:
                    matches.append({
                        "ip": ip,
                        "port": port,
                        "service_name": service_name,
                        "version": version,
                        "cve_id": cve["cve_id"],
                        "description": cve["description"]
                    })

        return matches

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
        version_match = re.search(r'(\d[\w\.\-_]*)', service_str)
        if version_match:
            version = version_match.group(1).strip()
            name = service_str.replace(version, '').strip(' -_')
            return name, version
        else:
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
                        if product not in ["*", "-", ""] and version not in ["*", "-", ""]:
                            products.append(product)
                            versions.append(version)
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

            nodes = item.get("configurations", {}).get("nodes", [])
            products, versions = extract_cpes(nodes)

            if products:
                for p, v in zip(products, versions):
                    key = (cve_id, p, v)
                    if key not in seen:
                        seen.add(key)
                        cves.append({
                            "cve_id": cve_id,
                            "description": description,
                            "product": p,
                            "version": v
                        })
            else:
                key = (cve_id, "", "")
                if key not in seen:
                    seen.add(key)
                    cves.append({
                        "cve_id": cve_id,
                        "description": description,
                        "product": "",
                        "version": ""
                    })

        return cves