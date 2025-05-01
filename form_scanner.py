import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

xss_payloads = ["<script>alert(1)</script>"]
sqli_payloads = ["' OR 1=1 --", "' AND SLEEP(5) --"]

sql_errors = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "sql syntax error"
]


def get_all_forms(url):
    try:
        res = requests.get(url, timeout=5)
        soup = BeautifulSoup(res.content, "html.parser")
        return soup.find_all("form")
    except Exception as e:
        print(f"[!] Error fetching forms from {url}: {e}")
        return []


def get_form_details(form):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []

    for input_tag in form.find_all("input"):
        name = input_tag.attrs.get("name")
        input_type = input_tag.attrs.get("type", "text")
        value = input_tag.attrs.get("value", "")
        if name:
            inputs.append({"name": name, "type": input_type, "value": value})

    details['action'] = action
    details['method'] = method
    details['inputs'] = inputs
    return details


def submit_form(form_details, url, payload):
    target_url = urljoin(url, form_details["action"])
    data = {}

    for input in form_details["inputs"]:
        if input["type"] == "text" or input["type"] == "search":
            data[input["name"]] = payload
        else:
            data[input["name"]] = input["value"]

    try:
        if form_details["method"] == "post":
            return requests.post(target_url, data=data, timeout=5)
        else:
            return requests.get(target_url, params=data, timeout=5)
    except Exception as e:
        print(f"[!] Failed to submit form at {target_url}: {e}")
        return None


def scan_forms(url):
    forms = get_all_forms(url)
    print(f"[+] Found {len(forms)} form(s) on {url}")
    results = []

    for form in forms:
        details = get_form_details(form)

        for payload in xss_payloads + sqli_payloads:
            response = submit_form(details, url, payload)
            if response and payload in response.text:
                print(f"[XSS] Reflected payload found on {url} via form.")
                results.append((url, "XSS"))
            elif response and any(err in response.text.lower() for err in sql_errors):
                print(f"[SQLi] SQL error detected on {url} via form.")
                results.append((url, "SQLi"))

    return results
