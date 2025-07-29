import ipaddress
from categories.analysis.methods_analysis import config_checker, default_creds_checker

valid_methods = ['confc', 'defcc', 'all']

def validate_ip_range(ip_range):
    try:
        ipaddress.ip_network(ip_range, strict=False)
        return True
    except ValueError:
        print(f"[!] Error: Invalid IP or IP range '{ip_range}'")
        return False
    
def run(args):

    results = {}

    if args.method not in valid_methods:
        print("[!] Invalid method. Choose from: confc, defcc, all")
        return

    if not validate_ip_range(args.range):
        return
    
    if args.method in ['confc', 'all']:
        print("Running config checking...")
        results['confc'] = config_checker.run()
