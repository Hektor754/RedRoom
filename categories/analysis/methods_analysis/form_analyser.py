import os
import json
import csv
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

def run(base_url, file, timeout=5, retries=3, user_agent=None):
    results = []

    if file:
        data = load_urls_from_file(file)
        if not data:
            return results

        session = create_session_with_retries(retries)
        if user_agent is None:
            user_agent = 'WebCrawler/1.0 RedRoomTool(Educational purposes;)'
        session.headers.update({'User-Agent': user_agent})

        for url in data:
            try:
                response = session.get(url, timeout=timeout)

                if response.status_code != 200:
                    continue

                content_type = response.headers.get('Content-Type', '')
                if 'text/html' not in content_type:
                    continue

                html_content = response.text
                try:
                    soup = BeautifulSoup(html_content, 'html.parser')
                except Exception as e:
                    logger.warning(f"Error parsing HTML from {url}: {e}")
                    continue

                forms = soup.find_all('form')
                for i, form in enumerate(forms):
                    action = form.get('action')
                    method = form.get('method', 'get').lower()
                    inputs = []
                    for input_tag in form.find_all('input'):
                        inputs.append({
                            "name": input_tag.get('name'),
                            "type": input_tag.get('type', 'text')
                        })

                    results.append({
                        "url": url,
                        "form_index": i,
                        "action": action,
                        "method": method,
                        "inputs": inputs
                    })

            except requests.RequestException as e:
                logger.warning(f"Request failed for {url}: {e}")
    else:
        session = create_session_with_retries(retries)
        if user_agent is None:
            user_agent = 'WebCrawler/1.0 RedRoomTool(Educational purposes;)'
        session.headers.update({'User-Agent': user_agent})

        try:
            response = session.get(base_url, timeout=timeout)
            if response.status_code == 200 and 'text/html' in response.headers.get('Content-Type', ''):
                html_content = response.text
                try:
                    soup = BeautifulSoup(html_content, 'html.parser')
                except Exception as e:
                    logger.warning(f"Error parsing HTML from {base_url}: {e}")
                    return results

                forms = soup.find_all('form')
                for i, form in enumerate(forms):
                    action = form.get('action')
                    method = form.get('method', 'get').lower()
                    inputs = []
                    for input_tag in form.find_all('input'):
                        inputs.append({
                            "name": input_tag.get('name'),
                            "type": input_tag.get('type', 'text')
                        })

                    results.append({
                        "url": base_url,
                        "form_index": i,
                        "action": action,
                        "method": method,
                        "inputs": inputs
                    })
            else:
                logger.warning(f"Non-HTML content or bad status code at {base_url}")
        except requests.RequestException as e:
            logger.warning(f"Request failed for {base_url}: {e}")
        
    return results

