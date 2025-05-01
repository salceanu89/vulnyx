# Vulnyx

🐍 **Vulnyx** is a lightweight web vulnerability scanner built with Python, focused on detecting **Cross-Site Scripting (XSS)** and **SQL Injection (SQLi)** vulnerabilities. It offers both a **command-line interface (CLI)** and a **Flask-based web dashboard** for ease of use.

---

##  Features

- ✅ Detects basic **XSS** and **SQLi** vulnerabilities.
- ✅ Crawler module to discover web pages and links.
- ✅ Modular architecture: crawler, scanners, and reporting engine.
- ✅ Multi-format reports: **TXT**, **JSON**, **HTML**.
- ✅ Web dashboard with historical scan results.
- ✅ Dark mode, responsive UI, and download-ready reports.

---

## Screenshots

| Login Page                              | Scan Dashboard                                                                |
|-----------------------------------------|-------------------------------------------------------------------------------|
| Login Screenshot![img_1.png](img_1.png) | Dashboard Screenshot![img_2.png](img_2.png) |

---

##  Installation

1️⃣ **Clone the repo:**

bash
git clone https://github.com/salceanu89/vulnyx.git
cd vulnyx

2️⃣ (Optional) Create a virtual environment:

bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

3️⃣ Install dependencies:
bash
pip install -r requirements.txt

🚦 Usage
Run the web app:
bash
python vulnyx_web.py

Then visit: http://127.0.0.1:5000

Login:

Username	Password
admin	vu1nyx123

Run the scanner (CLI mode):

bash

python vulnyx.py --url http://example.com --txt --json


**roject Structure**

bash

![image](https://github.com/user-attachments/assets/95b55d2f-161d-4328-b60d-f012594e47f2)


**Features in Progress / Ideas**

Scheduled scans and automated notifications.

Advanced DOM XSS detection.

Login & session management for authenticated scans.

Risk scoring and remediation advice in reports.
**Disclaimer**

Vulnyx is intended for educational and ethical testing purposes only. Always obtain proper authorisation before scanning web applications.

**License**

MIT License.

**Author**

**Victor Salceanu** – https://github.com/salceanu89
