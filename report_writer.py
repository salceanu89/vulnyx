import os
import json
from datetime import datetime

DOWNLOAD_FOLDER = "static/reports"
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

def save_report_txt(xss_results, sqli_results):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{timestamp}.txt"
    filepath = os.path.join(DOWNLOAD_FOLDER, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(f"=== Vulnyx Scan Report ===\n")
        f.write(f"Timestamp: {timestamp}\n\n")

        f.write(">>> XSS Vulnerabilities:\n")
        for url in xss_results:
            f.write(f"[XSS] {url}\n")

        f.write("\n>>> SQL Injection Vulnerabilities:\n")
        for url in sqli_results:
            f.write(f"[SQLi] {url}\n")

    print(f"[+] TXT report saved to {filepath}")


def save_report_json(xss_results, sqli_results):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report = {
        "timestamp": timestamp,
        "xss": list(xss_results),
        "sqli": list(sqli_results)
    }

    filename = f"scan_report_{timestamp.replace(':', '-').replace(' ', '_')}.json"
    filepath = os.path.join(DOWNLOAD_FOLDER, filename)

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=4)

    print(f"\n[+] JSON report saved to {filepath}")


def save_report_html(xss_results, sqli_results):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"scan_report_{timestamp}.html"
    filepath = os.path.join(DOWNLOAD_FOLDER, filename)

    html = f"""
     <!DOCTYPE html>
     <html lang="en">
     <head>
         <meta charset="UTF-8">
         <title>Vulnyx Scan Report</title>
         <style>
             body {{
                 font-family: Arial, sans-serif;
                 background-color: #f4f4f4;
                 color: #333;
                 padding: 20px;
             }}
             h1 {{
                 text-align: center;
                 color: #444;
             }}
             .section {{
                 background-color: white;
                 padding: 15px;
                 border-radius: 8px;
                 margin-bottom: 20px;
                 box-shadow: 0 2px 4px rgba(0,0,0,0.1);
             }}
             .xss {{
                 color: #c0392b;
             }}
             .sqli {{
                 color: #f39c12;
             }}
             li {{
                 margin: 5px 0;
             }}
         </style>
     </head>
     <body>
         <h1>Vulnyx Scan Report</h1>

         <div class="section">
             <h2 class="xss">XSS Vulnerabilities ({len(xss_results)})</h2>
             <ul>
                 {''.join(f'<li>{url}</li>' for url in xss_results)}
             </ul>
         </div>

         <div class="section">
             <h2 class="sqli">SQL Injection Vulnerabilities ({len(sqli_results)})</h2>
             <ul>
                 {''.join(f'<li>{url}</li>' for url in sqli_results)}
             </ul>
         </div>
     </body>
     </html>
     """

    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n[+] HTML report saved to {filepath}")




