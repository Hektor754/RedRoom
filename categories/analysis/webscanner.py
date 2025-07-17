from categories.analysis.methods_analysis import (
    web_crawler as webcrawler,
    form_analyzer as form_analyser,
    xss_sql_fuzzer as sql_fuzzer,
    tech_detector as tech_detection
)

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
        results['crawler'] = webcrawler.run(url)

    if args.method in ['form', 'all']:
        print("[*] Running Form Analyzer...")
        results['forms'] = form_analyser.run(url)

    if args.method in ['sqlfuzz', 'all']:
        print("[*] Running SQL/XSS Fuzzer...")
        results['fuzz'] = sql_fuzzer.run(url)

    if args.method in ['techd', 'all']:
        print("[*] Running Technology Detection...")
        results['tech'] = tech_detection.run(url)

