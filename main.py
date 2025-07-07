from core.cli import parse_args
from categories.recon import hostscan,hostprofile,dnsenum,traceroute,subenum,portscan
from utils import print_welcome_stamp
import sys


def main():
    
    args = sys.argv[1:]

    if len(args) == 1 and args[0].lower() == "redroom":
        print_welcome_stamp()
        return
        
    args = parse_args()

    valid_categories = {"recon"}
    valid_tools = {"hostscan","hostprofile","dnsenum","traceroute","subenum","portscan"}

    if args.category not in valid_categories:
        print(f"[!] Error: Invalid category '{args.category}'. Valid options: {', '.join(valid_categories)}")
        return

    if args.tool not in valid_tools:
        print(f"[!] Error: Invalid tool '{args.tool}'. Valid options: {', '.join(valid_tools)}")
        return

    if args.category == "recon":
        if args.tool == "hostscan":
            try:
                hostscan.run(args)
            except Exception as e:
                print(f"[!] Unexpected error during scan: {e}")
        elif args.tool == "hostprofile":
            try:
                hostprofile.run(args)
            except Exception as e:
                print(f"[!] Unexpected error during scan: {e}")
        elif args.tool == "dnsenum":
            try:
                dnsenum.run(args)
            except Exception as e:
                print(f"[!] Unexpected error during scan: {e}")
        elif args.tool == "subenum":
            try:
                subenum.run(args)
            except Exception as e:
                print(f"[!] Unexpected error during scan: {e}")     
        elif args.tool == "traceroute":
            try:
                traceroute.run(args)
            except Exception as e:
                print(f"[!] Unexpected error during scan: {e}")
        elif args.tool == "portscan":
            try:
                portscan.run(args)
            except Exception as e:
                print(f"[!] Unexpected error during scan: {e}")



if __name__ == "__main__":
    main()