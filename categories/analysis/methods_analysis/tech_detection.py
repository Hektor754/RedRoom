import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import csv
import json
import os
import logging
import time
from urllib.parse import urljoin, urlparse
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
    """Validate and normalize URL"""
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

    # Header-based fingerprints
    if 'cloudflare' in response.headers.get("Server", "").lower():
        tech["technologies"].add("Cloudflare")
    if 'php' in tech['powered_by'].lower():
        tech["technologies"].add("PHP")
    if 'express' in tech['powered_by'].lower():
        tech["technologies"].add("Node.js (Express)")

    # HTML-based fingerprints
    if "wp-content" in html or "wp-includes" in html:
        tech["technologies"].add("WordPress")
    if "Drupal.settings" in html:
        tech["technologies"].add("Drupal")
    if "generator" in html.lower():
        match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if match:
            tech["technologies"].add(match.group(1))

    # JS libraries
    if "jquery" in html.lower():
        tech["technologies"].add("jQuery")
    if "react" in html.lower():
        tech["technologies"].add("React")
    if "angular" in html.lower():
        tech["technologies"].add("Angular")
    
    tech["technologies"] = list(tech["technologies"])  # Convert to list for JSON export
    return tech

def run(base_url, file, timeout=5, retries=3, rate_limit=0.5, user_agent=None, max_content_size=5*1024*1024):
    results = []
    stats = {
        'total_urls': 0,
        'successful_requests': 0,
        'failed_requests': 0,
        'forms_found': 0
    }

    if file:
        data = load_urls_from_file(file)
        if not data:
            return results, stats
        
        # Validate URLs
        data = [validate_url(url) for url in data]
        data = [url for url in data if url is not None]

        stats['total_urls'] = len(data)

        session = create_session_with_retries(retries)
        if user_agent is None:
            user_agent = 'TechDetection/2.0 (Educational purposes)'
        session.headers.update({
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })

        for i, url in enumerate(data):
            try:
                logger.info(f"Processing {i+1}/{len(data)}: {url}")
                
                response = session.get(url, timeout=timeout, stream=True)
                
                # Check content size
                content_length = response.headers.get('content-length')
                if content_length and int(content_length) > max_content_size:
                    logger.warning(f"Content too large for {url}: {content_length} bytes")
                    continue

                if response.status_code != 200:
                    stats['failed_requests'] += 1
                    continue

                content_type = response.headers.get('Content-Type', '')
                if 'text/html' not in content_type:
                    stats['failed_requests'] += 1
                    continue

                html_content = response.text
                if len(html_content) > max_content_size:
                    logger.warning(f"HTML content too large for {url}")
                    continue

                try:
                    soup = BeautifulSoup(html_content, 'html.parser')
                except Exception as e:
                    logger.warning(f"Error parsing HTML from {url}: {e}")
                    stats['failed_requests'] += 1
                    continue

                # Get page title for context
                page_title = soup.find('title')
                page_title = page_title.get_text(strip=True) if page_title else 'No title'

                forms = soup.find_all('form')
                stats['forms_found'] += len(forms)
                

                tech_info = analyze_technology(response, html_content)
                    
                results.append({
                    "url": base_url,
                    "page_title": page_title,
                    **tech_info
                })

                stats['successful_requests'] += 1
                
                # Rate limiting with exponential backoff for errors
                time.sleep(rate_limit)
                
            except requests.RequestException as e:
                logger.warning(f"Request failed for {url}: {e}")
                stats['failed_requests'] += 1
                # Exponential backoff on errors
                time.sleep(min(rate_limit * 2, 5.0))
    else:
        # Single URL processing
        base_url = validate_url(base_url)
        if not base_url:
            logger.error(f"Invalid URL: {base_url}")
            return results, stats
            
        stats['total_urls'] = 1
        
        session = create_session_with_retries(retries)
        if user_agent is None:
            user_agent = 'FormAnalyzer/2.0 (Educational purposes)'
        session.headers.update({
            'User-Agent': user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        })

        try:
            response = session.get(base_url, timeout=timeout, stream=True)
            
            # Check content size
            content_length = response.headers.get('content-length')
            if content_length and int(content_length) > max_content_size:
                logger.warning(f"Content too large: {content_length} bytes")
                return results, stats
            
            if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                html_content = response.text
                if len(html_content) > max_content_size:
                    logger.warning("HTML content too large")
                    return results, stats
                
                try:
                    soup = BeautifulSoup(html_content, 'html.parser')
                except Exception as e:
                    logger.warning(f"Error parsing HTML from {base_url}: {e}")
                    stats['failed_requests'] += 1
                    return results, stats

                # Get page title for context
                page_title = soup.find('title')
                page_title = page_title.get_text(strip=True) if page_title else 'No title'

                forms = soup.find_all('form')
                stats['forms_found'] = len(forms)
                

                tech_info = analyze_technology(response, html_content)
                    
                results.append({
                    "url": base_url,
                    "page_title": page_title,
                    **tech_info
                })
                
                stats['successful_requests'] = 1
            else:
                logger.warning(f"Non-HTML content or bad status code at {base_url}")
                stats['failed_requests'] = 1
        except requests.RequestException as e:
            logger.warning(f"Request failed for {base_url}: {e}")
            stats['failed_requests'] = 1
        
    return results, stats