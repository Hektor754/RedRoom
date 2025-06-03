import csv
import json
import os


def print_summary(results,scantype):
    total = len(results)
    active_hosts = sum(1 for r in results if r["status"] == "ACTIVE")
    down_hosts = total - active_hosts

    print(f"\n {scantype} scan summary: ")
    print(f"-Total hosts scanned: {total}")
    print(f"-Hosts active: {active_hosts}")
    print(f"-Hosts down: {down_hosts}")

def save_results_csv(results, filename):
    with open(filename, mode="w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["ip", "status"])
        writer.writeheader()
        writer.writerows(results)
    print(f"\n[+] results saved to {filename}")

def save_results_json(results,filename):
    with open(filename, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Results saved to {filename}")

def handle_scan_output(results, scantype, filename=None, ftype=None):
    print_summary(results, scantype=scantype)

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
        elif ftype == "csv":
            save_results_csv(results, filename)
        elif ftype == "json":
            save_results_json(results, filename)