from termcolor import colored
from colorama import Fore,Style
from itertools import zip_longest
import csv
import json
import os
import sys
import socket
import ipaddress
import ifaddr
import subprocess
import shutil
import platform
import re

def print_welcome_stamp():
    logo = r"""                                                                                        


                                                                                                                       
                                                                                                                       
                                                                                                                       
                                                                                                                       
                                                                                                                       
                                                                                                                       
    xxxûûxxxûˆˆˆˆˆˆ³ˆ³³                                                                   ˆ³ˆ³³³³³³³ûûûûxûûûxÆÆ      
    xxxxxûûxxiˆ³ˆ³ˆˆˆˆˆ³ˆˆ                                                           ˆ³ˆˆˆˆˆ³ˆ  ³³³ˆûûûûûûûxûÆÆ      
    xxxûûxûûx³ˆˆˆ³ˆ       ³³ˆ            ˆˆˆˆ                ³      ˆˆˆ           ˆˆˆ³³³        ³³³³xûûûûûûûûÆÆ      
    xxxûûûûûxˆˆˆˆˆˆˆˆˆˆˆˆ      ˆ           ˆˆˆˆˆˆˆ³ˆ        ³ˆ    ˆˆ³          ³ˆˆˆ³         ³  ˆ³³•ûûûûûûûûxÆÆ      
    xxûxûûûûûˆÆÆÆÆÆÆÆÆˆ³³ˆˆˆˆˆ³ˆ             ³³³ˆˆˆ³ˆ       ˆˆ   ˆˆˆ        ˆˆˆˆ        ³iÆÆÆÆÆÆÆÆÆÆÆûûxûûûûûûÆ      
    xxxûxûÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆˆˆˆˆ³³ˆˆˆˆ³         ˆˆ³³ˆÆ³      ³Æ³ˆ ˆˆˆˆ      ˆˆ        •ÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆûûûûxÆ      
    xxxøÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆ³ˆˆˆ³³ˆ³³ˆˆ   ˆˆˆˆ³wÆˆ³ˆˆ³ˆˆ³Æx³ˆ³³•ˆ³         ˆ•xÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆûûûø      
    xxÆÆÆÆÆÆÆûûûûûûÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆˆˆˆˆ³³ˆˆˆˆˆ³³³ÆÆˆˆˆˆˆ³ˆˆÆÆˆ³³xxˆˆˆˆˆˆ³³ÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆæÿûûûûûûûûÆÆÆÆÆÆÆxx      
    xxxÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆ³³ˆ³³³³ÆÆÆ³ˆˆˆˆˆ³tÆÆxûxûûxxÿÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆûûûûÆÆÆÆÆÆÆûûûû      
    xxxxxÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆûûûûÿûÿÿûûÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆûxxxxû      
    xxûxûûÆÆÆÆÆÆÆÆÆÆxxûxÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÆÿûÿÿûÿûÿûûûÿêÆÆÆÆÆÆÆÆÆÆÆÆÆøûÆÆÆÆÆÆÆÆÆÆÆÆûxûûÆÆÆÆÆÆÆÆÆûûxûxûxû      
    xxtxxûûûûûûÆÆÆûÆxw   ÆÆÆÆÆÆÆÆÆÆ ûxûÆÆÆêÆÆÆÆÆÆÆû³³³³³ˆ³ˆ³³ÿÿÆÆÆÆÆÆÆÆÆÆÿûÿ   ÆÆÆÆÆÆÆÆÆˆ  xêûxÆÆÆÆÆûûûûûûûûxxû      
    xxx³³³³³xÿÿøÆÆÆw³ˆÆx     wx     ûûÆøøøøøøêÆÆÆÆÆ³³       ³³æÆÆÆÆÆêêêêêêÆÆxi          ³ûê³³ûÆÆÆøÿøûûû³ˆ³xxxxû      
    xxx³³³³³³iÿÿÿêÆûûÿûûÿ³³•³³³³³³³ÿÿÿÿøøøøøøêøûÿÆÆ³ˆ       ³³ÆÆÿÿøÆêêêêêøêêêêêÿˆ³³³³³³³³xêêêÆæêêêˆˆˆ³ˆ³ˆ³xxxxÆ      
    xxxx³³³³³••iÿÿÿÿûÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿûû³•³³³ûûÿ³³       ³³Æÿÿûÿÿûˆøêêêêûÿÿûêêêêêøêêêêêêêêêêê³³³³ˆˆˆˆ³xûûûxÆ      
    Æxxxx³³•³³³³³xÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿû  ³³³³³³³ûûˆ³       ³³ÿûûÿÿûû³ˆ³³³êêêÿûûûûûûûûûûøêêêêê³ˆ³³³³³³³³³xxxxÆÆ      
    ÆÆxxxxx³³³ˆ³³³³³ÿÿÿÿÿÿÿÿÿÿÿÿÿÿÿûû   •ˆ³³³³³³³³ûˆ³       ³³ûÿûÿûûûÿ³³ˆ³³³³êêêûûûûûûûÿæøÿˆ³³³³³³ˆ³³³³ˆxxûxÆÆÆ      
    ÆÆÆxxxwx••³³³³³³•³³³iniiii³ˆ³      ˆ³³³ˆ³³³³³³³³³      ³³³ûÿûûÿûûû³³³³³ˆ³ˆ³³³³³³³³³³³ˆ³ˆ³³³ˆ³³ˆ³ˆ³xxxxxÆÆÆê      
    ÆÆÆÆwxxxxx³³³ˆ³³³³³³³³ˆ³³³         ³³³³³³³ˆ³³³³³ˆ      ³³³ÿÿûûûûûû³³ˆˆ³ˆ³ˆˆ³³³ˆ³³³³ˆ³³³³ˆˆ³³ˆˆˆˆxxxxûxÆÆÆÆæ      
    ÆÆÆÆÆxxxxxxt³³³³³³³³³³³            ³³³³³³•³³³³³ˆ³      ³³³ûÿûÿÿûûû³³³³³ˆ³³ˆˆˆ³ˆˆ³ˆ³³³³ˆ³³³³ˆ³³xxwxxxxÆÆÆÆÆÆ      
                                                                                                                                            
                                                                                                                                            
    ░▒▓███████▓▒░░▒▓████████▓▒░▒▓███████▓▒░░▒▓███████▓▒░░░▒▓██████▓▒░░░▒▓██████▓▒░░▒▓██████████████▓▒░░  
    ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░░░░░░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░░░░░░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓███████▓▒░░▒▓██████▓▒░░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░░░░░░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░░░░░░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░░░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░                                                                                                                  
                                                                                                                       
                                                                                                                       
                                                                                                                                                                                                                                                                         
    """

    tagline = "Recon tool inspired by the Marvel Red Room — stealth and precision."
    usage = "Usage: RedRoom -h for help"
    author = "by Nemes1s | https://github.com/Nemes1s/RedRoom"
    quote = '“In the shadows, we find the truth.”'

    print(Fore.LIGHTRED_EX + logo + Style.RESET_ALL)
    print(tagline)
    print(usage)
    print(author)
    print()
    print(quote)

def clear_console():
    if os.name == "nt":
        os.system("cls")
    else:
        os.system("clear")

def handle_maestro_ui():
    logo = r"""
                                                                 
                                                                 
                    ░░░░░░░░░▒░▒░░░░                                ░░░░░░            
                    ░▓▓▓▓███▓▓█▓█▓▓▓▓▒▒▒░░                         ░░▒▒▒▒░░░░           
                    ▒▓█████▓▓████▓██████▓▒▒░░░░░░░░       ░ ░░░▒▒▒▒▓▓▓▒▓▓▒░░░   
                        ░▒░▒▒▒▒▒▒▒▓▓▒▓▓▒▒▓▒▒▒▓▓▓▓▓▓▓▒▓▒▓▒▒▓█▓▓▓██▓▓▓█▓▒▒░░░░  
                        ░░▒▓▓▒█████████▓▒▒▒▓▓▓█████████▓█████▓███▓███▓▓▓▓▓▒░░   
                    ░▒▒▒▓█████▒▓██▒░▒▓▓▓████▓██████████████████▓████▓▓▓▓░▒▒   
                    ░░▒▒▓█████▓▒▒▒▒▒▒▓█▓████▓█▓█████████████████▓█████▓▓▓▒▒▒░░░  
                ░▒▒▓██▓▓▓▒▒  ▒▒▓▓▓█████▓▒▒▒▒░▒▓███████▓████▓████▓▓▓▓▓▓▓▒▒▒▒▒░  
                ░▓█████▒░  ░ ▒▒██▓▓▒▓▒▒▓██░ ▒░  ░▒███▓▓▓███▓██▓▓▒▓▓▓▓█▓▓▒▒▒░    
                ▒▒▒░     ░░▒████▒░▒▓█▓▒░  ▒     ░▓▒▓██████▓▓▓▓▒▒▒░░▒▒▒▒▒░░░   
                            ░▒▓███▓░░▓██▒▒░  ░░ ░▒▒▒▒██▓█████▓▓▓▒░      ░░░░     
                            ▒▓██▓▒░▒▓█▓▒ ▒░  ░▓░▒▓█████▓████▒░░░░                
                        ░▒█▓▒░░░▓▒▒░  ░░▒▓▓▒█████▓▓▓░░▒▒░  ░▒░                
                        ░▓███▒░░▒  ░░ ░▒████▓███▒░░░  ▒░░  ░░░                
                        ▒▓███░░▒▒  ░▒░▒█████░░     ░ ░░░░  ░░░                
                        ▒▓▓▒░  ▒░   ▓ ░▒▓▒  ▒      ▒ ░░░░  ░▒                 
                            ░░ ░░░  ▒  ░▒   ▒      ▒ ▒░░░  ░▒                 
                            ░░ ░▒░  ░   ▒   ░      ░░░░ ░  ░░                 
                                ▒  ▓░  ░░  ░░░▒▒▒░     ░░ ░░  ░▒░                
                                ▒  ▒▒  ░▒  ░▒▓███▓▒   ░▒░  ▒  ░░░                
                                ▒  ░▒  ░▒  ░▓████▓▒   ░▓▒ ░▒  ░░                 
                                ▒  ░▒  ░░   ▒▓███▓▒    ▒░  ▒  ▒▓░                
                            ░▒█▓░ ░░  ░    ▒▓██▒     ░░ ░▒░▒▓▓▒░               
                            ░▒▓█▓█▓▒░░  ░░  ░░▒▒▒▓▓░▒▒░▒░  ▒▓██▓█▓░              
                            ▒██░░▒██▓▒░▒▒▓▓█▓▒█████▓█████▓▒▓██░░██▓░             
                        ░▒▓▓░   ▒█▓▒████▓▒▒███████▒░▒▒▓▓▒█▓░  ▒▓▓▒             
                        ▒██░     ░▒▓░░░   ▒█████▓▓▒      ░░    ▒██▒            
                                            ░▓██████▒              ░░            
                                            ░▒▒▓▓▓▒░                            
                                            ░▒▒▓██▓█▓░                           
                                            ▒▓█████▓▓░                           
                                            ░▓▓▓▓▓▒▒▓▒                           
                                            ░░░▒▒░▒░░░                           

    ░▒▓██████████████▓▒░ ░▒▓██████▓▒░░▒▓████████▓▒░░▒▓███████▓▒░▒▓████████▓▒░▒▓███████▓▒░ ░▒▓██████▓▒░  
    ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░         ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓██████▓▒░  ░▒▓██████▓▒░   ░▒▓█▓▒░   ░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░             ░▒▓█▓▒░  ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░▒▓███████▓▒░   ░▒▓█▓▒░   ░▒▓█▓▒░░▒▓█▓▒░░▒▓██████▓▒░  
                                                                                                        
    """
    available_options = list(range(1, 9))
    selection = """ 1) SQL Injection
                    2) Malware Attack
                    3) Phishing Attack
                    4) Brute Attack
                    5) Dos Attack
                    6) File Uploads
                    7) API / Mobile Backends
                    8) Post‑Exploitation (payloads)
                """
    
    while True:
        clear_console()
        print(logo)
        print(selection)

        try:
            user_input = input("Select one (press a number from 1 to 8): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nInput cancelled.")
            return None

        try:
            choice = int(user_input)
        except ValueError:
            print("Please enter a number 1–8. Press Enter to try again.")
            input()
            continue

        if choice not in available_options:
            print("Choice out of range — press Enter to try again.")
            input()
            continue

        clear_console()
        if choice == 1:
            print("1. Attack with a provided payload")
            print("2. Create custom payload")
            try:
                choice1_input = input("Select one: ")
            except (EOFError, KeyboardInterrupt):
                print("\nInput cancelled.")
                return None
            try:
                sql_inj_choice = int(choice1_input)
            except ValueError:
                print("Please pick a number between 1 or 2. Press Enter to try again.")
                input()
                continue

            if sql_inj_choice != (1 or 2):
                print("Choice out of range — press Enter to try again.")
                input()
                continue

        return choice

def print_tech_results(results):
    if not results:
        print("[!] No technologies detected.")
        return

    print("\n" + "=" * 80)
    print("TECHNOLOGY DETECTION RESULTS")
    print("=" * 80)

    for idx, item in enumerate(results, 1):
        print(f"\n[{idx}] URL: {item.get('url', 'N/A')}")
        print(f"     Title       : {item.get('page_title', 'No title')}")
        print(f"     Server      : {item.get('server', 'Unknown') or 'Unknown'}")
        print(f"     Powered By  : {item.get('powered_by', 'Unknown') or 'Unknown'}")
        
        techs = item.get('technologies', [])
        if techs:
            print(f"     Technologies: {', '.join(sorted(techs))}")
        else:
            print(f"     Technologies: None detected")

    print("\n" + "=" * 80)
    print(f"Total URLs analyzed: {len(results)}")
    print("=" * 80)

def print_sql_fuzzer_results(results):
    if not results:
        print("[!] No SQL injection findings.")
        return

    print(f"\n[+] {len(results)} SQL injection attempts completed.\n")

    for res in results:
        print(f"[*] URL: {res.get('target_url')}")
        print(f"    - Method: {res.get('method')}")
        print(f"    - Field: {res.get('field')}")
        print(f"    - Payload: {res.get('payload')}")
        print(f"    - Category: {res.get('category')}")
        print(f"    - Status Code: {res.get('status_code')}")
        print(f"    - Response Time: {res.get('response_time')}s")
        print(f"    - Confidence: {res.get('confidence_level')}")

        if res.get("vulnerability_indicators"):
            print(f"    - Indicators:")
            for ind in res["vulnerability_indicators"]:
                print(f"       · {ind}")

        if res.get("error"):
            print(f"    - Error: {res.get('error')}")

        print("─" * 50)

def print_crawl_results(results):
    print("\nCrawl Summary:")
    print(f"Pages Crawled: {results.get('pages_crawled', 0)}")
    print(f"Total Visited URLs: {results.get('total_visited', 0)}")
    print(f"Unique Found Links: {len(results.get('found_links', []))}")
    print(f"Skipped Links: {len(results.get('skipped_links', {}))}\n")

    if results.get('found_links'):
        print("Found Links:")
        for link in sorted(results['found_links']):
            print(f"  - {link}")
    else:
        print("No links found.")

    if results.get('skipped_links'):
        print("\nSkipped Links (with reasons):")
        for link, reason in sorted(results['skipped_links'].items()):
            print(f"  - {link} [{reason}]")
    else:
        print("No links skipped.")

def print_form_results(results):
    if not results:
        print("[*] No forms found.")
        return

    current_url = None
    for idx, form_data in enumerate(results, 1):
        url = form_data.get("url", "Unknown URL")
        page_title = form_data.get("page_title", "No title")

        if url != current_url:
            current_url = url
            print(f"\n{'='*80}")
            print(f"[*] Forms found on: {url}")
            print(f"[*] Page title: {page_title}")
            print(f"{'='*80}")

        form_index = form_data.get("form_index", 0)
        action = form_data.get("action") or "No action specified"
        method = form_data.get("method", "GET").upper()
        form_type = form_data.get("form_type", "unknown")
        complexity_score = form_data.get("complexity_score", 0)
        uses_https = form_data.get("uses_https", False)
        security_features = form_data.get("security_features", [])
        total_fields = form_data.get("total_fields", 0)

        print(f"\n  FORM #{form_index + 1}")
        print(f"    Action: {action}")
        print(f"    Method: {method}")
        print(f"    Type: {form_type.upper()}")
        print(f"    Total Fields: {total_fields}")
        print(f"    Complexity Score: {complexity_score}")
        print(f"    Uses HTTPS: {'Yes' if uses_https else 'No'}")
        
        if security_features:
            print(f"    Security Features: {', '.join(security_features)}")

        # Input fields
        inputs = form_data.get("inputs", [])
        if inputs:
            print(f"\n    INPUT FIELDS ({len(inputs)}):")
            for input_tag in inputs:
                name = input_tag.get("name", "unnamed")
                input_type = input_tag.get("type", "text")
                placeholder = input_tag.get("placeholder", "")
                required = "[REQUIRED]" if input_tag.get("required") else ""
                value = input_tag.get("value", "")
                
                print(f"      - Name: '{name}', Type: '{input_type}' {required}")
                if placeholder:
                    print(f"        Placeholder: '{placeholder}'")
                if value:
                    print(f"        Default Value: '{value}'")

        selects = form_data.get("selects", [])
        if selects:
            print(f"\n    SELECT DROPDOWNS ({len(selects)}):")
            for select_tag in selects:
                name = select_tag.get("name", "unnamed")
                option_count = select_tag.get("option_count", 0)
                multiple = select_tag.get("multiple", False)
                required = "[REQUIRED]" if select_tag.get("required") else ""
                
                print(f"      - Name: '{name}', Options: {option_count} {required}")
                if multiple:
                    print(f"        Multiple selections allowed")

                options = select_tag.get("options", [])[:3]
                for option in options:
                    selected = "[*]" if option.get("selected") else "[ ]"
                    print(f"        {selected} {option.get('text', '')} (value: {option.get('value', '')})")
                if select_tag.get("option_count", 0) > 3:
                    print(f"        ... and {select_tag.get('option_count') - 3} more options")

        textareas = form_data.get("textareas", [])
        if textareas:
            print(f"\n    TEXTAREA FIELDS ({len(textareas)}):")
            for textarea_tag in textareas:
                name = textarea_tag.get("name", "unnamed")
                placeholder = textarea_tag.get("placeholder", "")
                required = "[REQUIRED]" if textarea_tag.get("required") else ""
                rows = textarea_tag.get("rows", "")
                cols = textarea_tag.get("cols", "")
                
                print(f"      - Name: '{name}' {required}")
                if rows or cols:
                    print(f"        Size: {rows}x{cols}")
                if placeholder:
                    print(f"        Placeholder: '{placeholder}'")

        # Buttons
        buttons = form_data.get("buttons", [])
        if buttons:
            print(f"\n    BUTTONS ({len(buttons)}):")
            for button_tag in buttons:
                name = button_tag.get("name", "unnamed")
                button_type = button_tag.get("type", "button")
                text = button_tag.get("text", "")
                value = button_tag.get("value", "")
                
                print(f"      - Type: '{button_type}', Name: '{name}'")
                if text:
                    print(f"        Text: '{text}'")
                elif value:
                    print(f"        Value: '{value}'")

        print(f"\n    {'-'*50}")

def print_statistics(stats):
    """Print analysis statistics"""
    print(f"\n{'='*50}")
    print(f"ANALYSIS STATISTICS")
    print(f"{'='*50}")
    print(f"Total URLs processed: {stats.get('total_urls', 0)}")
    print(f"Successful requests: {stats.get('successful_requests', 0)}")
    print(f"Failed requests: {stats.get('failed_requests', 0)}")
    print(f"Total forms found: {stats.get('forms_found', 0)}")
    
    if stats.get('total_urls', 0) > 0:
        success_rate = (stats.get('successful_requests', 0) / stats.get('total_urls', 1)) * 100
        print(f"Success rate: {success_rate:.1f}%")

def print_cve_matches(matches):
    if not matches:
        print("No CVEs found.")
        return

    for match in matches:
        print(f"[!] CVE FOUND: {match['cve_id']}")
        print(f"    → Host: {match['ip']}:{match['port']}")
        print(f"    → Service: {match['service_name']} {match.get('version', '')}")
        print(f"    → Description: {match['description']}\n")


def print_portscan_results(all_results):
    for scan_type, results in all_results.items():
        print(colored(f"\n=== Scan Type: {scan_type.upper()} ===", "cyan", attrs=["bold"]))

        if not results:
            print(colored("No results found.\n", "red"))
            continue

        for entry in results:
            ip = entry.get("ip", "Unknown IP")
            open_ports = entry.get("open_ports", [])
            filtered_ports = entry.get("filtered_ports", [])
            services = entry.get("services", [])

            print(colored(f"\n| IP: {ip}", "magenta", attrs=["bold"]))

            if open_ports:
                print(colored("| Open Ports:", "cyan", attrs=["bold"]))
                for svc in services:
                    port = svc.get("port", "Unknown")
                    banner = svc.get("banner", "")
                    banner_display = f": {banner}" if banner else ""
                    print(colored(f"| - Port {port}{banner_display}", "cyan"))
            else:
                print(colored("  No open ports detected.", "yellow"))

            if filtered_ports:
                print(colored("| Filtered Ports:", "yellow", attrs=["bold"]))
                for port in filtered_ports:
                    print(colored(f"| - Port {port}", "yellow"))
            else:
                print(colored("  No filtered ports detected.", "red"))

            print(colored("-" * 40, "blue"))
            
def print_asn_results(ip, result):
    print("\n" + "=" * 40)
    print(f"[+] ASN Results for: {ip}")
    print("=" * 40)

    if not result:
        print("[-] No ASN information found or lookup failed.")
        return

    fields_to_print = {
        "ASN": result.get("asn"),
        "Description": result.get("asn_description"),
        "Country": result.get("asn_country_code"),
        "Network Name": result.get("network_name"),
        "CIDR": result.get("network_cidr")
    }

    for key, value in fields_to_print.items():
        print(f"{key}: {value if value else 'N/A'}")
        
def print_whois_results(target, result):
    print("\n" + "=" * 40)
    print(f"[+] WHOIS Results for: {target}")
    print("=" * 40)

    if not result:
        print("[-] No WHOIS information found or lookup failed.")
        return

    if isinstance(result, dict):
        for key, value in result.items():
            if isinstance(value, list):
                value = ', '.join(str(v) for v in value)
            print(f"{key}: {value}")
    else:
        print(str(result))
        
def print_zone_transfer_results(results):
    if not results:
        print("[!] No zone transfer data found.")
        return

    for ns_server, records in results.items():
        print(f"\n=== Zone transfer from: {ns_server} ===")
        if not records:
            print("  No records found.")
            continue

        if isinstance(records[0], dict):
            for rec in records:
                rec_name = rec.get("name", "")
                rec_type = rec.get("type", "")
                rec_data = rec.get("records", [])
                print(f"  {rec_name:30} {rec_type:6} {', '.join(rec_data)}")
        else:
            for rec_name in records:
                print(f"  {rec_name}")

    print("\n[+] Zone transfer printing complete.\n")
       
def print_hostprofile_results(results):
    print("\n" + "=" * 60)
    for i, host in enumerate(results, 1):
        print(f"{Fore.CYAN}Host #{i}{Style.RESET_ALL}")
        print("-" * 60)

        print(f"{Fore.YELLOW}Hostname{Style.RESET_ALL}    : {host.get('hostname', 'Unknown')}")
        print(f"{Fore.YELLOW}IP{Style.RESET_ALL}          : {host.get('ip', 'Unknown')}")
        print(f"{Fore.YELLOW}MAC{Style.RESET_ALL}         : {host.get('mac', 'Unknown')}")
        print(f"{Fore.YELLOW}Vendor{Style.RESET_ALL}      : {host.get('vendor', 'Unknown')}")

        os_data = host.get('os_data', {})
        primary_guess = os_data.get('primary_guess', 'Unknown')
        confidence = os_data.get('confidence', 'unknown').lower()

        if confidence == "high":
            confidence_color = Fore.GREEN
        elif confidence == "medium":
            confidence_color = Fore.YELLOW
        else:
            confidence_color = Fore.RED

        print(f"{Fore.YELLOW}OS{Style.RESET_ALL}          : {primary_guess}")
        print(f"{Fore.YELLOW}Confidence{Style.RESET_ALL}  : {confidence_color}{confidence.upper()}{Style.RESET_ALL}")

        if os_data.get('alternatives'):
            print(f"{Fore.YELLOW}Also Possible{Style.RESET_ALL}: {', '.join(os_data['alternatives'])}")

        if os_data.get('window_size') and os_data.get('ttl'):
            print(f"{Fore.YELLOW}Detection{Style.RESET_ALL}   : Window={os_data['window_size']}, TTL={os_data['ttl']}")

        status = host.get('status', 'INACTIVE').upper()
        status_color = Fore.GREEN if status == "ACTIVE" else Fore.RED
        print(f"{Fore.YELLOW}Status{Style.RESET_ALL}      : {status_color}{status}{Style.RESET_ALL}")

        ports = host.get('ports', [])
        services = host.get('services', [])

        if ports:
            print(f"{Fore.YELLOW}Open Ports{Style.RESET_ALL}:")
            for port, service in zip(ports, services):
                print(f"  {Fore.BLUE}{port:<5}{Style.RESET_ALL} {service}")
        else:
            print(f"{Fore.YELLOW}Open Ports{Style.RESET_ALL}: None detected")

        print("=" * 60)

def print_summary(results,scantype):
    total = len(results)
    active_hosts = sum(1 for r in results if r["status"] == "ACTIVE")
    down_hosts = total - active_hosts

    print(f"\n {scantype} scan summary: ")
    print(f"-Total hosts scanned: {total}")
    print(f"-Hosts active: {active_hosts}")
    print(f"-Hosts inactive: {down_hosts}")

def print_sub_passive_results(results):
    all_subdomains = results.get("all", [])
    per_source = results.get("per_source", {})

    print("\n" + "=" * 60)
    print(f"[+] Total Unique Subdomains Found: {len(all_subdomains)}")
    print("=" * 60 + "\n")

    for source, subdomains in per_source.items():
        count = len(subdomains)
        print(f"  [•] {source.capitalize():<15} → {count} subdomain{'s' if count != 1 else ''}")

    print("\n" + "-" * 60)
    print("[+] Combined Subdomains List:")
    print("-" * 60 + "\n")

    for sub in sorted(all_subdomains):
        print(f"  - {sub}")

    print("\n" + "=" * 60 + "\n")

def print_sub_brute_results(domain, found_subdomains, total_attempts):
    print("\n" + "=" * 60)
    print(f"[+] Brute-Force Subdomain Enumeration Results for: {domain}")
    print("=" * 60)
    
    print(f"[•] Total Attempts Made: {total_attempts}")
    print(f"[•] Total Valid Subdomains Found: {len(found_subdomains)}")
    
    if found_subdomains:
        print("\n" + "-" * 60)
        print("[+] Discovered Subdomains:")
        print("-" * 60)
        for sub in sorted(found_subdomains):
            print(f"  └─ {sub}")
    else:
        print("\n[-] No subdomains found via brute-force.")

    print("=" * 60 + "\n")
    
    
def sanitize_results(results):
    sanitized = {}
    for key, val in results.items():
        if val is None:
            sanitized[key] = []
        else:
            sanitized[key] = val
    return sanitized

def save_results_json(results,filename):
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Results saved to {filename}")

def save_dns_results_json(results, filename):
    results = sanitize_results(results)
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] DNS results saved to {filename}")

def save_results_json_brute(results, filename):
    found_subdomains, wordlist_count = results
    data = {
        "wordlist_count": wordlist_count,
        "subdomains_found_count": len(found_subdomains),
        "subdomains": found_subdomains
    }
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"\n[+] Brute force results saved to {filename}")

def save_results_csv(results, filename):
    with open(filename, mode="w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["hostname", "ip", "status"])
        writer.writeheader()
        writer.writerows(results)
    print(f"\n[+] results saved to {filename}")

def save_cve_results_csv(results, filename):
    keys = results[0].keys()

    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(results)
    
def save_dns_results_csv(results, filename):
    results = sanitize_results(results)
    flat_records = []

    for record_type, value in results.items():
        if isinstance(value, list):
            for entry in value:
                flat_records.append({
                    "record_type": record_type,
                    "value": str(entry)
                })
        elif isinstance(value, dict):
            flat_records.append({
                "record_type": record_type,
                "value": json.dumps(value)
            })
        else:
            flat_records.append({
                "record_type": record_type,
                "value": str(value)
            })

    with open(filename, mode="w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["record_type", "value"])
        writer.writeheader()
        writer.writerows(flat_records)

    print(f"\n[+] DNS results saved to {filename}")
    
def save_subenum_results_csv_brute(results, filename):
    found_subdomains, wordlist_count = results
    with open(filename, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([f"Total wordlist entries: {wordlist_count}"])
        writer.writerow([f"Total subdomains found: {len(found_subdomains)}"])
        writer.writerow([])
        writer.writerow(["Subdomains Found"])
        
        for sub in found_subdomains:
            writer.writerow([sub])
    print(f"\n[+] Brute force results saved to {filename}")
    
def save_trrt_results_csv(results, filename):
    with open(filename, mode="w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["hop", "ip", "latency"])
        writer.writeheader()
        writer.writerows(results)
    print(f"\n[+] results saved to {filename}")
    
def save_subenum_results_csv(results, filename):
    sources = list(results.get("per_source", {}).keys())
    columns = [results["per_source"].get(src, []) for src in sources]

    rows = zip_longest(*columns, fillvalue="")

    with open(filename, mode="w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(sources)
        for row in rows:
            writer.writerow(row)
    print(f"\n[+] Results saved to {filename}")

def save_webcrawl_csv(results, filename):
    found_links = results.get("found_links", [])
    skipped_links = results.get("skipped_links", {})

    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "status", "reason"])

        for link in found_links:
            writer.writerow([link, "found", ""])

        for link, reason in skipped_links.items():
            writer.writerow([link, "skipped", reason])

    print(f"\n[+]Results saved to {filename}")


def save_sql_results_csv(results, filename):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "target_url", "method", "field", "payload", "category",
            "status_code", "response_time", "content_length",
            "confidence_level", "vulnerability_indicators", "error"
        ])

        for res in results:
            writer.writerow([
                res.get("target_url", ""),
                res.get("method", ""),
                res.get("field", ""),
                res.get("payload", ""),
                res.get("category", ""),
                res.get("status_code", ""),
                res.get("response_time", ""),
                res.get("content_length", ""),
                res.get("confidence_level", ""),
                "; ".join(res.get("vulnerability_indicators", [])),
                res.get("error", "")
            ])
    print(f"\n[+] SQLi results saved to {filename}")


def save_form_results_csv(results, filename):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        # Enhanced header with new fields
        writer.writerow([
            "url", "page_title", "form_index", "method", "action", "form_type", 
            "complexity_score", "security_features", "element_type", "element_name", 
            "element_value", "element_required", "element_placeholder", "additional_info"
        ])
        
        for form in results:
            url = form.get("url", "")
            page_title = form.get("page_title", "")
            index = form.get("form_index", "")
            method = form.get("method", "GET")
            action = form.get("action", "")
            form_type = form.get("form_type", "unknown")
            complexity_score = form.get("complexity_score", 0)
            security_features = ", ".join(form.get("security_features", []))
            
            # Write input elements
            inputs = form.get("inputs", [])
            for input_tag in inputs:
                writer.writerow([
                    url, page_title, index, method, action, form_type, complexity_score,
                    security_features, "input", input_tag.get("name", ""),
                    input_tag.get("value", ""), input_tag.get("required", False),
                    input_tag.get("placeholder", ""), f"type: {input_tag.get('type', 'text')}"
                ])
            
            # Write select elements
            selects = form.get("selects", [])
            for select_tag in selects:
                options_info = f"options: {select_tag.get('option_count', 0)}"
                writer.writerow([
                    url, page_title, index, method, action, form_type, complexity_score,
                    security_features, "select", select_tag.get("name", ""), "",
                    select_tag.get("required", False), "", options_info
                ])
            
            # Write textarea elements
            textareas = form.get("textareas", [])
            for textarea_tag in textareas:
                size_info = f"rows: {textarea_tag.get('rows', '')}, cols: {textarea_tag.get('cols', '')}"
                writer.writerow([
                    url, page_title, index, method, action, form_type, complexity_score,
                    security_features, "textarea", textarea_tag.get("name", ""), 
                    textarea_tag.get("content", ""), textarea_tag.get("required", False),
                    textarea_tag.get("placeholder", ""), size_info
                ])
            
            # Write button elements
            buttons = form.get("buttons", [])
            for button_tag in buttons:
                button_info = f"type: {button_tag.get('type', 'button')}"
                writer.writerow([
                    url, page_title, index, method, action, form_type, complexity_score,
                    security_features, "button", button_tag.get("name", ""),
                    button_tag.get("value", ""), False, "", button_info
                ])
    
    print(f"\n[+] Enhanced form analysis results saved to {filename}")

def save_tech_results_csv(results, filename):
    with open(filename, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "page_title", "server", "powered_by", "technologies"])
        for item in results:
            writer.writerow([
                item.get("url", ""),
                item.get("page_title", ""),
                item.get("server", ""),
                item.get("powered_by", ""),
                ", ".join(item.get("technologies", []))
            ])
    print(f"\n[+] Technology detection results saved to {filename}")

def handle_scan_output(results, scantype, filename=None, ftype=None):
    if ftype and not filename:
        filename = f"scan_output.{ftype}"
    if filename and not ftype:
        ext = os.path.splitext(filename)[1].lower()
        if ext == ".csv":
            ftype = "csv"
        elif ext == ".json":
            ftype = "json"

    if filename:
        if ftype not in ("csv", "json"):
            print(f"[!] Unsupported output format: {ftype}")
        if scantype == "dnsenum":
            results = sanitize_results(results)
            if ftype == "csv":
                save_dns_results_csv(results, filename)
            elif ftype == "json":
                save_dns_results_json(results, filename)
        elif scantype == "traceroute":
            if ftype == "csv":
                save_trrt_results_csv(results, filename)
            elif ftype == "json":
                save_results_json(results, filename) 
        elif scantype == "subenum":
            if isinstance(results, dict) and "all" in results and "per_source" in results:
                if ftype == "csv":
                    save_subenum_results_csv(results, filename)
                else:
                    save_results_json(results, filename)
            elif isinstance(results, tuple) and len(results) == 2:
                if ftype == "csv": 
                    save_subenum_results_csv_brute(results, filename)
                else: 
                    save_results_json_brute(results, filename)
            else:
                print("[!] Unknown results format, cannot save.") 
        elif scantype == "cvelookup":
            if ftype == "csv":
                save_cve_results_csv(results, filename)
            elif ftype == "json":
                save_results_json(results, filename)     
        elif scantype == "webcrawler":
            if ftype == "csv":
                save_webcrawl_csv(results, filename)
            elif ftype == "json":
                save_results_json(results, filename) 
        elif scantype == "formanalyser":
            if ftype == "csv":
                save_form_results_csv(results, filename)
            elif ftype == "json":
                save_results_json(results, filename)   
        elif scantype == "sqlfuzzer":
            if ftype == "csv":
                save_sql_results_csv(results, filename)
            elif ftype == "json":
                save_results_json(results, filename)
        elif scantype == "techdetection":
            if ftype == "csv":
                save_tech_results_csv(results, filename)
            elif ftype == "json":
                save_results_json(results, filename)                                  
        else:
            if ftype == "csv":
                save_results_csv(results, filename)
            elif ftype == "json":
                save_results_json(results, filename)
            
        

def resolve_hostname(target_ip):
    if isinstance(target_ip, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        target_ip = str(target_ip)

    try:
        target_addr = ipaddress.ip_address(target_ip)
    except ValueError:
        return "Invalid IP"
    
    def mdns_lookup():
        if shutil.which("avahi-resolve-address") is None:
            return "Unknown"
        try:
            output = subprocess.check_output(
                ["avahi-resolve-address", target_ip],
                stderr=subprocess.DEVNULL,
                timeout=2,
                encoding='utf-8'                
            )
            parts = output.strip().split()
            if len(parts) >= 2:
                return parts[1]
        except Exception:
            pass
        return None

    def netbios_lookup_nmblookup():
        if shutil.which("nmblookup") is None:
            return None
        adapters = ifaddr.get_adapters()
        for adapter in adapters:
            for ip in adapter.ips:
                if not isinstance(ip.ip, str):
                    continue
                try:
                    network = ipaddress.ip_network(f"{ip.ip}/{ip.network_prefix}", strict=False)
                except ValueError:
                    continue
                if target_addr in network:
                    try:
                        output = subprocess.check_output(
                            ['nmblookup', '-A', target_ip],
                            stderr=subprocess.DEVNULL,
                            timeout=3
                        ).decode(errors='ignore')
                        for line in output.splitlines():
                            if '<00>' in line and 'GROUP' not in line:
                                parts = line.strip().split()
                                if parts:
                                    return parts[0]
                    except Exception:
                        continue
        return None

    def netbios_lookup_nbtstat():
        if platform.system() != "Windows":
            return None
        try:
            output = subprocess.check_output(
                ['nbtstat', '-A', target_ip],
                stderr=subprocess.DEVNULL,
                timeout=3,
                encoding='utf-8',
                errors='ignore'
            )
            for line in output.splitlines():
                if '<00>' in line and 'UNIQUE' in line.upper():
                    parts = re.split(r'\s+', line.strip())
                    if parts:
                        return parts[0]
        except Exception:
            return None
        return None

    try:
        hostname, _, _ = socket.gethostbyaddr(target_ip)
        if hostname:
            return hostname
    except Exception:
        pass

    hostname = netbios_lookup_nmblookup()
    if hostname:
        return hostname

    hostname = netbios_lookup_nbtstat()
    if hostname:
        return hostname
    
    hostname = mdns_lookup()
    if hostname:
        return hostname

    try:
        fqdn = socket.getfqdn(target_ip)
        if fqdn and fqdn != target_ip:
            hostname = fqdn
            return hostname
    except Exception:
        pass

    return "Unknown"