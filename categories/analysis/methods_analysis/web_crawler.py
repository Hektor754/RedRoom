from collections import deque
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, parse_qs
from urllib.robotparser import RobotFileParser
import time
import logging
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

BLACKLIST_KEYWORDS = [
    'ads', 'doubleclick', 'tracker', 'analytics',
    'facebook.com', 'twitter.com', 'instagram.com', 'youtube.com',
    'click', 'popup', 'sponsor', 'affiliate', 'redirect', 'outbrain',
    'googlesyndication', 'adservice.google', 'adserver', 'adnetwork',
    '.gif', '.jpg', '.png', '.ico', '.svg', '.mp4', '.mp3', '.avi',
    '.exe', '.zip', '.rar', '.7z', '.pdf', '.css', '.js'
]

def has_suspicious_query_params(url):
    query = urlparse(url).query
    params = parse_qs(query)
    suspicious_params = {'utm_source', 'utm_medium', 'utm_campaign', 'ref', 'affiliate', 'fbclid', 'gclid'}
    return any(param in suspicious_params for param in params)

def is_allowed_domain(url, allowed_domains):
    domain = urlparse(url).netloc
    return any(domain == allowed or domain.endswith('.' + allowed) for allowed in allowed_domains)

def create_session_with_retries(retries=3, backoff_factor=0.3):
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

def run(base_url, max_depth=2, timeout=5.0, retries=3, allowed_domains=None, 
        delay=1.0, max_pages=100, user_agent=None):

    if allowed_domains is None:
        allowed_domains = [urlparse(base_url).netloc]

    to_visit = deque()
    to_visit.append((base_url, 0))
    visited = set()
    found_links = set()
    skipped_links = {}
    pages_crawled = 0

    parsed_base = urlparse(base_url)
    base_domain = parsed_base.netloc
    base_scheme = parsed_base.scheme
    base_root = f"{base_scheme}://{base_domain}"
    robots_url = urljoin(base_root, '/robots.txt')

    # Set up robots.txt parser
    rp = RobotFileParser()
    rp.set_url(robots_url)
    try:
        rp.read()
        logger.info(f"Loaded robots.txt from {robots_url}")
    except Exception as e:
        logger.warning(f"Could not load robots.txt: {e}")
        rp = None

    # Create session with retry strategy
    session = create_session_with_retries(retries)
    
    # Set user agent
    if user_agent is None:
        user_agent = f'WebCrawler/1.0 RedRoomTool(Educational purposes; +{base_root})'
    
    session.headers.update({'User-Agent': user_agent})

    logger.info(f"Starting crawl of {base_url} with max_depth={max_depth}")

    while to_visit and pages_crawled < max_pages:
        current_url, depth = to_visit.popleft()

        if depth > max_depth or current_url in visited:
            continue

        # Check robots.txt
        if rp and not rp.can_fetch("*", current_url):
            skipped_links[current_url] = 'disallowed by robots.txt'
            continue

        visited.add(current_url)
        pages_crawled += 1

        # Rate limiting
        if delay > 0:
            time.sleep(delay)

        try:
            logger.info(f"Crawling: {current_url} (depth: {depth})")
            response = session.get(current_url, timeout=timeout, allow_redirects=True)

            # Check if we were redirected to external domain
            final_domain = urlparse(response.url).netloc
            if not is_allowed_domain(response.url, allowed_domains):
                skipped_links[response.url] = 'redirected to external domain'
                continue

            if response.status_code == 200:
                content_type = response.headers.get('Content-Type', '')
                if 'text/html' in content_type:
                    html_content = response.text
                else:
                    skipped_links[current_url] = 'not HTML content'
                    continue
            else:
                skipped_links[current_url] = f'HTTP {response.status_code}'
                continue

        except requests.RequestException as e:
            logger.warning(f"Error crawling {current_url}: {e}")
            skipped_links[current_url] = f'request error: {str(e)}'
            continue

        # Parse HTML and extract links
        try:
            soup = BeautifulSoup(html_content, 'html.parser')
        except Exception as e:
            logger.warning(f"Error parsing HTML from {current_url}: {e}")
            continue

        links_found_on_page = 0
        for link_tag in soup.find_all('a', href=True):
            href = link_tag['href']
            absolute_link = urljoin(current_url, href)
            parsed_link = urlparse(absolute_link)

            # Skip non-HTTP(S) links
            if parsed_link.scheme not in ['http', 'https']:
                continue

            # Check domain restrictions
            if not is_allowed_domain(absolute_link, allowed_domains):
                skipped_links[absolute_link] = 'not in allowed domains'
                continue

            # Check blacklist
            if any(keyword in absolute_link.lower() for keyword in BLACKLIST_KEYWORDS):
                skipped_links[absolute_link] = 'blacklisted keyword'
                continue

            # Check suspicious parameters
            if has_suspicious_query_params(absolute_link):
                skipped_links[absolute_link] = 'suspicious query params'
                continue

            # Remove fragment identifier
            clean_link = absolute_link.split('#')[0]

            # Add to queue if not already visited
            if clean_link not in visited and clean_link not in found_links:
                to_visit.append((clean_link, depth + 1))
                found_links.add(clean_link)
                links_found_on_page += 1

        logger.info(f"Found {links_found_on_page} new links on {current_url}")

    logger.info(f"Crawling complete. Visited {pages_crawled} pages, found {len(found_links)} links")

    return {
        "found_links": list(found_links),
        "skipped_links": skipped_links,
        "pages_crawled": pages_crawled,
        "total_visited": len(visited)
    }