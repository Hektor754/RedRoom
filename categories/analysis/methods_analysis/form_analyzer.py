import os
import json
import csv
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import logging
import time
from urllib.parse import urljoin, urlparse
import re
import certifi

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

def classify_form(inputs):
    """Classify form based on inputs"""
    input_names = [inp.get('name', '').lower() for inp in inputs if inp.get('name')]
    input_types = [inp.get('type', '').lower() for inp in inputs]
    
    # Login form detection
    if ('password' in input_types and 
        any(name in input_names for name in ['username', 'email', 'login', 'user'])):
        return 'login'
    
    # Registration form detection
    if ('password' in input_types and 
        any(name in input_names for name in ['confirm', 'repeat', 'register', 'signup'])):
        return 'registration'
    
    # Contact form detection
    if any(name in input_names for name in ['message', 'comment', 'subject', 'contact']):
        return 'contact'
    
    # Search form detection
    if any(name in input_names for name in ['search', 'query', 'q']):
        return 'search'
    
    # Payment form detection
    if any(name in input_names for name in ['card', 'payment', 'billing', 'checkout']):
        return 'payment'
    
    return 'unknown'

def detect_security_features(form, inputs):
    """Detect security features in form"""
    security_features = []
    
    # CSRF token detection
    csrf_patterns = ['csrf', 'token', '_token', 'authenticity_token']
    for inp in inputs:
        if (inp.get('type') == 'hidden' and inp.get('name') and 
            any(pattern in inp.get('name', '').lower() for pattern in csrf_patterns)):
            security_features.append('csrf_token')
            break
    
    # Captcha detection
    if form.find(['img', 'iframe', 'div'], class_=re.compile(r'captcha', re.I)):
        security_features.append('captcha')
    
    # Required fields
    required_count = sum(1 for inp in inputs if inp.get('required'))
    if required_count > 0:
        security_features.append(f'required_fields_{required_count}')
    
    return security_features

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

def analyze_form(form, url):
    """Analyze a single form element and extract all details"""
    action = form.get('action')
    method = form.get('method', 'get').lower()
    
    # Get absolute action URL
    if action:
        action = urljoin(url, action)
    
    # Extract inputs with detailed information
    inputs = []
    for input_tag in form.find_all('input'):
        input_data = {
            "name": input_tag.get('name'),
            "type": input_tag.get('type', 'text'),
            "placeholder": input_tag.get('placeholder'),
            "value": input_tag.get('value'),
            "required": input_tag.has_attr('required'),
            "readonly": input_tag.has_attr('readonly'),
            "disabled": input_tag.has_attr('disabled'),
            "maxlength": input_tag.get('maxlength'),
            "minlength": input_tag.get('minlength'),
            "pattern": input_tag.get('pattern'),
            "id": input_tag.get('id'),
            "class": input_tag.get('class')
        }
        inputs.append(input_data)
    
    # Extract select elements with options
    selects = []
    for select_tag in form.find_all('select'):
        options = []
        for option_tag in select_tag.find_all('option'):
            options.append({
                "value": option_tag.get('value'),
                "text": option_tag.get_text(strip=True),
                "selected": option_tag.has_attr('selected')
            })
        
        select_data = {
            "name": select_tag.get('name'),
            "id": select_tag.get('id'),
            "multiple": select_tag.has_attr('multiple'),
            "required": select_tag.has_attr('required'),
            "disabled": select_tag.has_attr('disabled'),
            "options": options,
            "option_count": len(options)
        }
        selects.append(select_data)
    
    # Extract textarea elements
    textareas = []
    for textarea_tag in form.find_all('textarea'):
        textarea_data = {
            "name": textarea_tag.get('name'),
            "id": textarea_tag.get('id'),
            "placeholder": textarea_tag.get('placeholder'),
            "required": textarea_tag.has_attr('required'),
            "readonly": textarea_tag.has_attr('readonly'),
            "disabled": textarea_tag.has_attr('disabled'),
            "rows": textarea_tag.get('rows'),
            "cols": textarea_tag.get('cols'),
            "maxlength": textarea_tag.get('maxlength'),
            "content": textarea_tag.get_text(strip=True)
        }
        textareas.append(textarea_data)
    
    # Extract button elements
    buttons = []
    for button_tag in form.find_all(['button', 'input']):
        if button_tag.name == 'input' and button_tag.get('type') not in ['submit', 'button', 'reset']:
            continue
        
        button_data = {
            "type": button_tag.get('type', 'button'),
            "name": button_tag.get('name'),
            "value": button_tag.get('value'),
            "text": button_tag.get_text(strip=True) if button_tag.name == 'button' else button_tag.get('value', ''),
            "disabled": button_tag.has_attr('disabled'),
            "id": button_tag.get('id')
        }
        buttons.append(button_data)
    
    # Form classification and security analysis
    form_type = classify_form(inputs)
    security_features = detect_security_features(form, inputs)
    
    # Calculate complexity score
    complexity_score = len(inputs) + len(selects) * 2 + len(textareas) * 2
    
    return {
        "action": action,
        "method": method,
        "inputs": inputs,
        "selects": selects,
        "textareas": textareas,
        "buttons": buttons,
        "form_type": form_type,
        "security_features": security_features,
        "complexity_score": complexity_score,
        "total_fields": len(inputs) + len(selects) + len(textareas),
        "uses_https": action and action.startswith('https://') if action else False
    }

def run(base_url=None, file=None, timeout=5, retries=3, session=None,
        user_agent=None, rate_limit=0.5, max_content_size=5*1024*1024):
    results = []

    # Ensure session exists and is configured
    if session is None:
        session = create_session_with_retries(retries)
    # For lab/testing convenience, disable certificate verification to avoid
    # CERTIFICATE_VERIFY_FAILED errors on self-signed or incomplete chains.
    # Remove or change this in production if you want strict verification.
    session.verify = certifi.where()

    # Set / normalize user agent
    if user_agent is None:
        user_agent = 'FormAnalyzer/2.0 (Educational purposes)'
    session.headers.update({
        'User-Agent': user_agent,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    })

    # Build target URL list
    target_urls = []
    if file:
        try:
            data = load_urls_from_file(file)
        except Exception as e:
            logger.warning(f"Error loading URL file {file}: {e}")
            return results

        # normalize and validate URLs
        for u in data:
            validated = validate_url(u)
            if validated:
                target_urls.append(validated)
    elif base_url:
        validated = validate_url(base_url)
        if validated:
            target_urls.append(validated)
        else:
            logger.error(f"Invalid URL provided: {base_url}")
            return results
    else:
        # Nothing to do
        logger.error("No base_url or file provided to form_analyzer.run()")
        return results

    # Iterate URLs and extract forms
    for idx, url in enumerate(target_urls):
        try:
            logger.info(f"Processing ({idx+1}/{len(target_urls)}): {url}")
            resp = session.get(url, timeout=timeout, stream=True, verify=False)
            print(resp.text[:1000])

            # Basic response checks
            if resp.status_code != 200:
                logger.warning(f"Non-200 status for {url}: {resp.status_code}")
                continue

            content_type = resp.headers.get('Content-Type', '')
            if 'text/html' not in content_type:
                logger.warning(f"Non-HTML content at {url}: {content_type}")
                continue

            # Protect against enormous responses
            html_content = resp.text
            if len(html_content) > max_content_size:
                logger.warning(f"HTML content too large for {url} ({len(html_content)} bytes)")
                continue

            # Parse HTML
            try:
                soup = BeautifulSoup(html_content, 'html.parser')
            except Exception as e:
                logger.warning(f"Error parsing HTML from {url}: {e}")
                continue

            page_title_tag = soup.find('title')
            page_title = page_title_tag.get_text(strip=True) if page_title_tag else 'No title'

            forms = soup.find_all('form')
            if not forms:
                logger.debug(f"No forms found at {url}")
            for form_index, form in enumerate(forms):
                try:
                    form_data = analyze_form(form, url)

                    # Defensive sanity: ensure inputs is a list
                    if not isinstance(form_data.get("inputs", []), list):
                        logger.warning(f"Form inputs not a list at {url}, index {form_index}. Skipping.")
                        continue

                    # Return the form dict directly (structure expected by fuzzers)
                    results.append(form_data)

                except Exception as e:
                    logger.warning(f"Error analyzing form at {url} index {form_index}: {e}")
                    continue

            # polite rate limit between requests
            time.sleep(rate_limit)

        except requests.RequestException as e:
            logger.warning(f"Request failed for {url}: {e}")
            # small backoff on error
            time.sleep(min(rate_limit * 2, 5.0))
            continue
        except Exception as e:
            logger.warning(f"Unexpected error when processing {url}: {e}")
            continue

    return results

