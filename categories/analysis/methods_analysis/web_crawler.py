from collections import deque
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

def run(base_url, max_depth=2, timeout=2.0, retries=2):
    to_visit = deque()
    to_visit.append((base_url, 0))
    visited = set()
    found_links = set()

    while to_visit:
        current_url, depth = to_visit.popleft()

        if depth > max_depth:
            continue

        if current_url in visited:
            continue

        visited.add(current_url)

        for attempt in range(retries):
            try:
                response = requests.get(current_url, timeout=timeout)
                if response.status_code == 200:
                    html_content = response.text
                    break
            except requests.RequestException:
                pass
        else:
            continue

        soup = BeautifulSoup(html_content, 'html.parser')
        base_domain = urlparse(base_url).netloc

        for link_tag in soup.find_all('a', href=True):
            href = link_tag['href']
            absolute_link = urljoin(current_url, href)

            parsed_link = urlparse(absolute_link)
            if parsed_link.scheme not in ['http', 'https']:
                continue

            if not parsed_link.netloc.endswith(base_domain):
                continue

            clean_link = absolute_link.split('#')[0]

            if clean_link not in visited:
                to_visit.append((clean_link, depth + 1))
                found_links.add(clean_link)

    return list(found_links)