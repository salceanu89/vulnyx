from colorama import Fore, Style, init
init(autoreset=True)
from form_scanner import scan_forms
from report_writer import save_report_txt, save_report_json
from sqli_scanner import inject_sqli_payloads
from xss_scanner import inject_xss_payloads
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

visited = set()

def is_valid_url(url, base_domain):
    parsed = urlparse(url)
    return parsed.netloc == base_domain and url not in visited

def crawl(base_url):
    to_visit = [base_url]
    base_domain = urlparse(base_url).netloc
    discovered_links = []

    while to_visit:
        current = to_visit.pop()
        if current in visited:
            continue
        visited.add(current)

        try:
            response = requests.get(current, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            discovered_links.append(current)

            for link in soup.find_all('a', href=True):
                full_url = urljoin(current, link['href'])
                if is_valid_url(full_url, base_domain):
                    to_visit.append(full_url)
        except Exception as e:
            print(f"[!] Failed to crawl {current}: {e}")

    return discovered_links

if __name__ == "__main__":
    start_url = input("Enter the base URL: ")
    links = crawl(start_url)

    all_xss = set()
    all_sqli = set()

    for link in links:
        print(link)

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
            elif vuln_type == "SQLi":
                all_sqli.add(form_url)
    for form_url, vuln_type in form_results:
        if vuln_type == "XSS":
            all_xss.add(form_url)
            print(Fore.RED + f"[XSS-Form] {form_url}")
        elif vuln_type == "SQLi":
            all_sqli.add(form_url)
            print(Fore.YELLOW + f"[SQLi-Form] {form_url}")

    # Save to files
    save_report_txt(all_xss, all_sqli)
    save_report_json(all_xss, all_sqli)



