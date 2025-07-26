import argparse
from .methods_recon.dns_resolve.subdomain_resolve import Subdomain_Lookup
import Essentials.utils as utils


def parse_dns_flags(extra_args):
    parser_subenum = argparse.ArgumentParser(prog="subenum", add_help=False)
    parser_subenum.add_argument('--securitytrails-key', type=str, help='API key for SecurityTrails')
    parser_subenum.add_argument('--virustotal-key', type=str, help='API key for VirusTotal')
    parser_subenum.add_argument('--certspotter-key', type=str, help='API key for Certspotter')
    parser_subenum.add_argument('--alienvault-key', type=str, help='API key for AlienVault')
      
    args, unknown = parser_subenum.parse_known_args(extra_args)
    
    args.extra = unknown 
    
    if unknown:
        print(f"[!] Warning: Unknown Subdomain enumeration options ignored: {unknown}")
        
    return args

def run(args):
    dns_flags = parse_dns_flags(args.extra)
        
    sources_to_use = []


    if not args.domain:
        print("[!] Error: No domain specified")
        return

    domain = args.domain
    method = args.method
    
    if method == "passive":
        sources_to_use.extend(['crtsh', 'threatcrowd'])
            
        if dns_flags.securitytrails_key:
            sources_to_use.append('securitytrails')
        if dns_flags.virustotal_key:
            sources_to_use.append('virustotal')  
        if dns_flags.certspotter_key:
            sources_to_use.append('certspotter') 

        api_keys = {
            k: v for k, v in {
                'securitytrails': dns_flags.securitytrails_key,
                'virustotal': dns_flags.virustotal_key,
                'certspotter': dns_flags.certspotter_key,
                'alienvault': dns_flags.alienvault_key
            }.items() if v is not None
        }
        
        results = Subdomain_Lookup.run(sources_to_use,domain, api_keys=api_keys)
        utils.print_sub_passive_results(results)
        
        utils.handle_scan_output(results,scantype="subenum",filename=args.output,ftype=args.format)
        
    elif method == "brute": 
        wordlist = "Essentials/subdomains-top1million-5000.txt"
        subdom, attempts = Subdomain_Lookup.bruteforce(domain, wordlist)
        results = (subdom, attempts)
        utils.print_sub_brute_results(domain,results, attempts)
        utils.handle_scan_output(results,scantype="subenum",filename=args.output,ftype=args.format)
        
        