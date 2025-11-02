from categories.analysis.methods_analysis import form_analyzer, web_crawler, xss_sql_fuzzer, tech_detection
from Essentials.utils import (
    print_crawl_results, handle_scan_output, print_form_results,
    print_sql_fuzzer_results, print_tech_results
)
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import requests

valid_methods = ['wcrawl', 'form', 'sqlfuzz', 'techd', 'all']

def _create_shared_session(retries=3, backoff_factor=0.3):
    s = requests.Session()
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        respect_retry_after_header=True
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    s.mount("http://", adapter)
    s.mount("https://", adapter)
    s.headers.update({
        'User-Agent': 'RedRoomScanner/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
    })
    return s

def run(args):
    if getattr(args, 'method', None) not in valid_methods:
        print("[!] Invalid method. Choose from: wcrawl, form, sqlfuzz, techd, all")
        return

    url = getattr(args, 'url', None)
    if not url:
        print("[!] Missing URL. Please provide with -u or --url.")
        return

    # sensible defaults
    timeout = getattr(args, 'timeout', 5.0) or 5.0
    retries = getattr(args, 'retries', 3) or 3
    max_workers = getattr(args, 'max_workers', 3) or 3
    delay = getattr(args, 'delay', 0.5) or 0.5
    output = getattr(args, 'output', None)
    fmt = getattr(args, 'format', None)
    infile = getattr(args, 'file', None)

    results = {}
    session = _create_shared_session(retries=retries)

    # Web Crawl
    if args.method in ['wcrawl', 'all']:
        try:
            print("[*] Running Web Crawler...")
            results['crawler'] = web_crawler.run(url, timeout=timeout, retries=retries, session=session)
            print_crawl_results(results['crawler'])
            handle_scan_output(results['crawler'], scantype="webcrawler", filename=output, ftype=fmt)
        except Exception as e:
            print(f"[!] Web crawler error: {e}")

    # Form Analyzer
    if args.method in ['form', 'all']:
        try:
            print("[*] Running Form Analyzer...")
            results['forms'] = form_analyzer.run(url, infile, timeout=timeout, retries=retries, session=session)
            print_form_results(results['forms'])
            handle_scan_output(results['forms'], scantype="formanalyser", filename=output, ftype=fmt)
        except Exception as e:
            print(f"[!] Form analyzer error: {e}")

    # SQL/XSS Fuzzer
    if args.method in ['sqlfuzz', 'all']:
        try:
            print("[*] Running SQL/XSS Fuzzer...")
            # pass the same session and values so behavior is consistent
            results['fuzz'] = xss_sql_fuzzer.run(
                base_url=url,
                file=infile,
                timeout=timeout,
                retries=retries,
                session=session,
                max_workers=max_workers,
                delay=delay,
                output_file=output if output else None
            )
            print_sql_fuzzer_results(results['fuzz'])
            handle_scan_output(results['fuzz'], scantype="sqlfuzzer", filename=output, ftype=fmt)
        except Exception as e:
            print(f"[!] SQL/XSS fuzzer error: {e}")

    # Technology Detection
    if args.method in ['techd', 'all']:
        try:
            print("[*] Running Technology Detection...")
            results['tech'] = tech_detection.run(url, timeout=timeout, retries=retries, session=session)
            print_tech_results(results['tech'])
            handle_scan_output(results['tech'], scantype="techdetection", filename=output, ftype=fmt)
        except Exception as e:
            print(f"[!] Tech detection error: {e}")

    return results
