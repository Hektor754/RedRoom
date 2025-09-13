import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import csv
import json
import os
import logging
import time
from urllib.parse import urlparse
import re

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

def load_urls_from_file(filepath):
    urls = []
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"File not found: {filepath}")

    ext = os.path.splitext(filepath)[-1].lower()

    if ext == ".json":
        with open(filepath, "r") as f:
            data = json.load(f)
            if isinstance(data, list):
                urls = data
            elif isinstance(data, dict):
                urls = data.get("found_links", [])

    elif ext == ".csv":
        with open(filepath, "r", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                for key in ("link", "url", "found_links"):
                    if key in row:
                        urls.append(row[key])
                        break
    else:
        raise ValueError("Unsupported file type. Use .json or .csv")

    return list(set(urls))

def validate_url(url):
    if not url or not isinstance(url, str):
        return None
    url = url.strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return None
        return url
    except Exception:
        return None

def analyze_technology(response, html):
    tech = {
        "server": response.headers.get("Server", ""),
        "powered_by": response.headers.get("X-Powered-By", ""),
        "technologies": set()
    }

    headers = {k.lower(): v.lower() for k, v in response.headers.items()}

    if "cloudflare" in headers.get("server", ""):
        tech["technologies"].add("Cloudflare")
    if "php" in tech['powered_by'].lower() or "php" in headers.get("set-cookie", ""):
        tech["technologies"].add("PHP")
    if "express" in tech['powered_by'].lower():
        tech["technologies"].add("Node.js (Express)")
    if "asp.net" in tech['powered_by'].lower() or "asp.net" in headers.get("x-aspnet-version", ""):
        tech["technologies"].add("ASP.NET")
    if "django" in tech['powered_by'].lower():
        tech["technologies"].add("Django")

    if "wp-content" in html or "wp-includes" in html:
        tech["technologies"].add("WordPress")
    if "Drupal.settings" in html:
        tech["technologies"].add("Drupal")
    if "Joomla!" in html:
        tech["technologies"].add("Joomla")
    if "generator" in html.lower():
        match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if match:
            tech["technologies"].add(match.group(1))

    if re.search(r"jquery(\.min)?\.js", html, re.I):
        tech["technologies"].add("jQuery")
    if re.search(r"react(\.min)?\.js", html, re.I):
        tech["technologies"].add("React")
    if re.search(r"angular(\.min)?\.js", html, re.I):
        tech["technologies"].add("Angular")

    tech["technologies"] = list(tech["technologies"])
    return tech

def run(base_url=None, file=None, timeout=5, retries=3, rate_limit=0.5, user_agent=None, max_content_size=5*1024*1024):
    results = []
    stats = {
        'total_urls': 0,
        'successful_requests': 0,
        'failed_requests': 0,
        'forms_found': 0
    }

    urls = []
    if file:
        urls = load_urls_from_file(file)
        urls = [validate_url(url) for url in urls if validate_url(url)]
    elif base_url:
        validated = validate_url(base_url)
        if validated:
            urls = [validated]

    if not urls:
        logger.error("No valid URLs to process.")
        return results, stats

    stats['total_urls'] = len(urls)
    session = create_session_with_retries(retries)
    if user_agent is None:
        user_agent = 'TechDetector/2.0 (Educational purposes)'
    session.headers.update({
        'User-Agent': user_agent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    })

    for i, url in enumerate(urls):
        try:
            logger.info(f"Processing {i+1}/{len(urls)}: {url}")
            response = session.get(url, timeout=timeout)

            if response.status_code != 200:
                stats['failed_requests'] += 1
                continue

            content_type = response.headers.get('Content-Type', '')
            if 'text/html' not in content_type:
                stats['failed_requests'] += 1
                continue

            html_content = response.text
            if len(html_content.encode('utf-8')) > max_content_size:
                logger.warning(f"HTML content too large for {url}")
                continue

            try:
                soup = BeautifulSoup(html_content, 'html.parser')
            except Exception as e:
                logger.warning(f"Error parsing HTML from {url}: {e}")
                stats['failed_requests'] += 1
                continue

            page_title = soup.find('title')
            page_title = page_title.get_text(strip=True) if page_title else 'No title'

            forms = soup.find_all('form')
            stats['forms_found'] += len(forms)

            tech_info = analyze_technology(response, html_content)

            results.append({
                "url": url,
                "page_title": page_title,
                **tech_info
            })

            stats['successful_requests'] += 1
            time.sleep(rate_limit)

        except requests.RequestException as e:
            logger.warning(f"Request failed for {url}: {e}")
            stats['failed_requests'] += 1
            time.sleep(min(rate_limit * 2, 5.0))

    return results, stats