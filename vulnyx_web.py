import os
import time
from glob import glob
from flask import Flask, render_template, request, redirect, url_for, session
from crawler import crawl
from xss_scanner import inject_xss_payloads
from sqli_scanner import inject_sqli_payloads
from form_scanner import scan_forms
from report_writer import save_report_txt, save_report_json, save_report_html

app = Flask(__name__)
app.secret_key = 'supersecretkey'

def get_latest_report(extension):
    files = glob(f"static/reports/*.{extension}")
    return max(files, key=os.path.getctime).split("static/")[1] if files else None

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username == "admin" and password == "vu1nyx123":
            session["logged_in"] = True
            return redirect(url_for("index"))
        else:
            error = "Invalid credentials. Try again."
    return render_template("login.html", error=error)

@app.route("/scan", methods=["GET", "POST"])
def index():
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    xss_results = []
    sqli_results = []
    scanned_url = ""
    start_time = time.time()

    if request.method == "POST":
        scanned_url = request.form.get("target_url")
        links = crawl(scanned_url)

        for link in links:
            xss = inject_xss_payloads(link)
            if xss:
                xss_results.extend(xss)

            sqli = inject_sqli_payloads(link)
            if sqli:
                sqli_results.extend(sqli)

            form_results = scan_forms(link)
            for form_url, vuln_type in form_results:
                if vuln_type == "XSS":
                    xss_results.append(form_url)
                elif vuln_type == "SQLi":
                    sqli_results.append(form_url)

        save_report_txt(xss_results, sqli_results)
        save_report_json(xss_results, sqli_results)
        save_report_html(xss_results, sqli_results)

    end_time = time.time()
    scan_duration = round(end_time - start_time, 2)

    return render_template(
        "index.html",
        url=scanned_url,
        xss_results=set(xss_results),
        sqli_results=set(sqli_results),
        scan_duration=scan_duration,
        latest_txt=get_latest_report("txt"),
        latest_html=get_latest_report("html")
    )

@app.route("/dashboard")
def dashboard():
    import json
    if not session.get("logged_in"):
        return redirect(url_for("login"))

    report_files = sorted(os.listdir("static/reports"), reverse=True)
    reports = []

    for file in report_files:
        if file.endswith(".json"):
            with open(f"static/reports/{file}") as f:
                data = json.load(f)
                reports.append({
                    "file": file,
                    "timestamp": data.get("timestamp", "Unknown"),
                    "xss_count": len(data.get("XSS_Vulnerabilities", [])),
                    "sqli_count": len(data.get("SQLi_Vulnerabilities", []))
                })

    return render_template("dashboard.html", reports=reports)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)

