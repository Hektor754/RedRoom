from categories.analysis.methods_analysis import (
    web_crawler as webcrawler,
    form_analyser as form_analyser,
    xss_sql_fuzzer as sql_fuzzer,
    tech_detector as tech_detection
)
from utils import print_crawl_results,handle_scan_output,print_form_results

valid_methods = ['wcrawl', 'form', 'sqlfuzz', 'techd', 'all']

def run(args):
    if args.method not in valid_methods:
        print("[!] Invalid method. Choose from: wcrawl, form, sqlfuzz, techd, all")
        return

    url = getattr(args, 'url', None)
    if not url:
        print("[!] Missing URL. Please provide with -u or --url.")
        return

    results = {}

    if args.method in ['wcrawl', 'all']:
        print("[*] Running Web Crawler...")
        if not args.timeout:
            args.timeout = 5.0
        if not args.retries:
            args.retries = 3
        results['crawler'] = webcrawler.run(url, args.timeout, args.retries)
        print_crawl_results(results['crawler'])
        handle_scan_output(results['crawler'], scantype="webcrawler", filename=args.output, ftype=args.format)
        
    if args.method in ['form', 'all']:
        if not args.timeout:
            args.timeout = 5.0
        if not args.retries:
            args.retries = 3
        print("[*] Running Form Analyzer...")
        results['forms'] = form_analyser.run(url, args.file, args.timeout, args.retries)
        print_form_results(results['forms'])
        handle_scan_output(results['forms'], scantype="formanalyser", filename=args.output, ftype=args.format)
    if args.method in ['sqlfuzz', 'all']:
        print("[*] Running SQL/XSS Fuzzer...")
        results['fuzz'] = sql_fuzzer.run(url)

    if args.method in ['techd', 'all']:
        print("[*] Running Technology Detection...")
        results['tech'] = tech_detection.run(url)

