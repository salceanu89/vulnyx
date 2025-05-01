import argparse
from crawler import crawl
from xss_scanner import inject_xss_payloads
from sqli_scanner import inject_sqli_payloads
from form_scanner import scan_forms
from report_writer import save_report_txt, save_report_json
from report_writer import save_report_html
from colorama import Fore, Style, init

init(autoreset=True)

def run_scan(base_url, save_txt, save_json):
    print(Fore.CYAN + f"\n[+] Starting Vulnyx scan on: {base_url}")

    links = crawl(base_url)
    all_xss = set()
    all_sqli = set()

    for link in links:
        print(Fore.BLUE + f"\n[~] Scanning: {link}")

        xss_results = inject_xss_payloads(link)
        if xss_results:
            all_xss.update(xss_results)
            for result in xss_results:
                print(Fore.RED + f"[XSS] {result}")

        sqli_results = inject_sqli_payloads(link)
        if sqli_results:
            all_sqli.update(sqli_results)
            for result in sqli_results:
                print(Fore.YELLOW + f"[SQLi] {result}")

        form_results = scan_forms(link)
        for form_url, vuln_type in form_results:
            if vuln_type == "XSS":
                all_xss.add(form_url)
                print(Fore.RED + f"[XSS-Form] {form_url}")
            elif vuln_type == "SQLi":
                all_sqli.add(form_url)
                print(Fore.YELLOW + f"[SQLi-Form] {form_url}")

    if save_txt:
        save_report_txt(all_xss, all_sqli)
    if save_json:
        save_report_json(all_xss, all_sqli)
    save_report_html(all_xss, all_sqli)

    print(Fore.GREEN + "\n[✓] Vulnyx scan complete!")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vulnyx - Web Vulnerability Scanner")
    parser.add_argument("--url", required=True, help="Target base URL to scan")
    parser.add_argument("--txt", action="store_true", help="Save TXT report")
    parser.add_argument("--json", action="store_true", help="Save JSON report")

    args = parser.parse_args()
    run_scan(args.url, args.txt, args.json)
