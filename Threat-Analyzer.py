import os
import re
import hashlib
import magic
import shutil
import tkinter as tk
import email

from tkinter import filedialog, messagebox, simpledialog
from urllib.parse import urlparse
from datetime import datetime
from email import policy
from email.parser import BytesParser
from oletools.olevba import VBA_Parser

# Gmail API Imports
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
import base64
import pickle


# =====================================================
# CONFIGURATION
# =====================================================

SCOPES = ['https://www.googleapis.com/auth/gmail.readonly']

DANGEROUS_EXTENSIONS = [
    ".exe",
    ".bat",
    ".scr",
    ".js",
    ".vbs",
    ".cmd",
    ".ps1"
]

SUSPICIOUS_KEYWORDS = [
    "urgent",
    "invoice",
    "payment",
    "bank",
    "password",
    "update",
    "security",
    "payroll",
    "crypto",
    "wallet"
]

SAFE_TYPES = {
    ".pdf": "PDF",
    ".txt": "ASCII",
    ".jpg": "JPEG",
    ".jpeg": "JPEG",
    ".png": "PNG",
    ".docx": "Microsoft Word",
    ".xlsx": "Microsoft Excel"
}

MIN_SIZE = 2048
MAX_SIZE = 100 * 1024 * 1024

URL_REGEX = r'(https?://[^\s]+)'

QUARANTINE_FOLDER = "quarantine"
LOG_FOLDER = "logs"

os.makedirs(QUARANTINE_FOLDER, exist_ok=True)
os.makedirs(LOG_FOLDER, exist_ok=True)


# =====================================================
# GREETING
# =====================================================

def get_greeting():

    current_hour = datetime.now().hour

    if current_hour < 12:
        return "Good Morning"

    elif current_hour < 18:
        return "Good Afternoon"

    return "Good Evening"


# =====================================================
# SHA256 HASH
# =====================================================

def generate_sha256(file_path):

    sha256 = hashlib.sha256()

    try:

        with open(file_path, "rb") as file:

            while chunk := file.read(4096):
                sha256.update(chunk)

        return sha256.hexdigest()

    except Exception as e:

        return f"Hash Error: {e}"


# =====================================================
# EXTENSION CHECK
# =====================================================

def check_extension(filename):

    alerts = []
    score = 0

    lower_name = filename.lower()

    for ext in DANGEROUS_EXTENSIONS:

        if lower_name.endswith(ext):

            alerts.append(
                f"Dangerous extension detected: {ext}"
            )

            score += 40

    parts = lower_name.split(".")

    if len(parts) >= 3:

        alerts.append(
            "Suspicious double extension detected"
        )

        score += 25

    return alerts, score


# =====================================================
# FILE TYPE CHECK
# =====================================================

def check_file_type(file_path):

    alerts = []
    score = 0

    try:

        mime = magic.Magic(mime=False)
        real_type = mime.from_file(file_path)

        _, ext = os.path.splitext(file_path)
        ext = ext.lower()

        if ext in SAFE_TYPES:

            expected = SAFE_TYPES[ext]

            if expected.lower() not in real_type.lower():

                alerts.append(
                    f"File type mismatch detected "
                    f"(Expected {expected}, Got {real_type})"
                )

                score += 50

        return alerts, score, real_type

    except Exception as e:

        return [f"Type Check Error: {e}"], 0, "Unknown"


# =====================================================
# FILE SIZE
# =====================================================

def check_file_size(file_path):

    alerts = []
    score = 0

    try:

        size = os.path.getsize(file_path)

        if size == 0:

            alerts.append("Empty file detected")
            score += 30

        elif size < MIN_SIZE:

            alerts.append(
                f"Suspiciously small file ({size} bytes)"
            )

            score += 15

        elif size > MAX_SIZE:

            alerts.append(
                f"Unusually large file ({size} bytes)"
            )

            score += 15

        return alerts, score, size

    except Exception as e:

        return [f"Size Error: {e}"], 0, 0


# =====================================================
# SUSPICIOUS FILENAMES
# =====================================================

def check_suspicious_filename(filename):

    alerts = []
    score = 0

    lower_name = filename.lower()

    for keyword in SUSPICIOUS_KEYWORDS:

        if keyword in lower_name:

            alerts.append(
                f"Suspicious keyword detected: {keyword}"
            )

            score += 20

    return alerts, score


# =====================================================
# HIDDEN EXTENSIONS
# =====================================================

def check_hidden_extensions(filename):

    alerts = []
    score = 0

    if re.search(r'\.\w+\s+\.', filename):

        alerts.append(
            "Possible hidden extension trick detected"
        )

        score += 25

    if '\u202e' in filename:

        alerts.append(
            "Unicode extension spoofing detected"
        )

        score += 40

    return alerts, score


# =====================================================
# MACRO DETECTION
# =====================================================

def check_macros(file_path):

    alerts = []
    score = 0

    try:

        vbaparser = VBA_Parser(file_path)

        if vbaparser.detect_vba_macros():

            alerts.append(
                "Embedded VBA macro detected"
            )

            score += 30

        vbaparser.close()

    except Exception:
        pass

    return alerts, score


# =====================================================
# METADATA
# =====================================================

def inspect_metadata(file_path):

    alerts = []

    try:

        created = os.path.getctime(file_path)
        modified = os.path.getmtime(file_path)

        created_time = datetime.fromtimestamp(created)
        modified_time = datetime.fromtimestamp(modified)

        alerts.append(f"Created: {created_time}")
        alerts.append(f"Last Modified: {modified_time}")

    except Exception as e:

        alerts.append(f"Metadata Error: {e}")

    return alerts, 0


# =====================================================
# URL EXTRACTION
# =====================================================

def extract_urls_from_content(content):

    alerts = []
    score = 0

    suspicious_domains = [
        "bit.ly",
        "tinyurl",
        "goo.gl"
    ]

    urls = re.findall(URL_REGEX, content)

    for url in urls:

        alerts.append(f"URL Found: {url}")

        parsed = urlparse(url)
        domain = parsed.netloc.lower()

        for shortener in suspicious_domains:

            if shortener in domain:

                alerts.append(
                    f"Shortened URL detected: {url}"
                )

                score += 25

        if re.match(
            r'^\d+\.\d+\.\d+\.\d+$',
            domain
        ):

            alerts.append(
                f"Raw IP address URL detected: {url}"
            )

            score += 30

    return alerts, score


# =====================================================
# RISK CLASSIFICATION
# =====================================================

def classify_risk(score):

    if score >= 80:
        return "HIGH RISK"

    elif score >= 40:
        return "MEDIUM RISK"

    return "LOW RISK"


# =====================================================
# RECOMMENDATION ENGINE
# =====================================================

def get_recommendation(risk_level):

    recommendations = {

        "LOW RISK":
        "Content appears mostly safe.",

        "MEDIUM RISK":
        "Avoid interacting until manually reviewed.",

        "HIGH RISK":
        "Quarantine or delete immediately."
    }

    return recommendations[risk_level]


# =====================================================
# QUARANTINE
# =====================================================

def quarantine_file(file_path):

    try:

        filename = os.path.basename(file_path)

        destination = os.path.join(
            QUARANTINE_FOLDER,
            filename
        )

        shutil.copy(file_path, destination)

        return (
            f"File moved to quarantine:\n{destination}"
        )

    except Exception as e:

        return f"Quarantine Error: {e}"


# =====================================================
# LOGGING
# =====================================================

def save_log(report):

    log_name = datetime.now().strftime(
        "%Y-%m-%d_%H-%M-%S.txt"
    )

    log_path = os.path.join(
        LOG_FOLDER,
        log_name
    )

    with open(log_path, "w") as log:
        log.write(report)


# =====================================================
# FILE ANALYZER
# =====================================================

def analyze_file(file_path):

    filename = os.path.basename(file_path)

    all_alerts = []
    risk_score = 0

    ext_alerts, ext_score = (
        check_extension(filename)
    )

    all_alerts.extend(ext_alerts)
    risk_score += ext_score

    name_alerts, name_score = (
        check_suspicious_filename(filename)
    )

    all_alerts.extend(name_alerts)
    risk_score += name_score

    hidden_alerts, hidden_score = (
        check_hidden_extensions(filename)
    )

    all_alerts.extend(hidden_alerts)
    risk_score += hidden_score

    type_alerts, type_score, real_type = (
        check_file_type(file_path)
    )

    all_alerts.extend(type_alerts)
    risk_score += type_score

    size_alerts, size_score, size = (
        check_file_size(file_path)
    )

    all_alerts.extend(size_alerts)
    risk_score += size_score

    sha256_hash = generate_sha256(file_path)

    macro_alerts, macro_score = (
        check_macros(file_path)
    )

    all_alerts.extend(macro_alerts)
    risk_score += macro_score

    meta_alerts, meta_score = (
        inspect_metadata(file_path)
    )

    all_alerts.extend(meta_alerts)
    risk_score += meta_score

    risk_level = classify_risk(risk_score)

    recommendation = get_recommendation(
        risk_level
    )

    report = f"""
====================================================
                FILE ANALYSIS REPORT
====================================================

File Name      : {filename}
Actual Type    : {real_type}
File Size      : {size} bytes
SHA256         : {sha256_hash}

Risk Score     : {risk_score}
Risk Level     : {risk_level}

Recommendation :
{recommendation}

----------------------------------------------------
"""

    for alert in all_alerts:
        report += f"\n[!] {alert}"

    report += (
        "\n\n===================================================="
    )

    save_log(report)

    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, report)


# =====================================================
# GMAIL AUTHENTICATION
# =====================================================

def gmail_authenticate():

    creds = None

    if os.path.exists("token.pickle"):

        with open("token.pickle", "rb") as token:
            creds = pickle.load(token)

    if not creds or not creds.valid:

        if creds and creds.expired and creds.refresh_token:

            creds.refresh(Request())

        else:

            flow = InstalledAppFlow.from_client_secrets_file(
                "credentials.json",
                SCOPES
            )

            creds = flow.run_local_server(port=0)

        with open("token.pickle", "wb") as token:
            pickle.dump(creds, token)

    service = build(
        "gmail",
        "v1",
        credentials=creds
    )

    return service


# =====================================================
# EMAIL ANALYZER
# =====================================================

def analyze_gmail():

    try:

        service = gmail_authenticate()

        results = service.users().messages().list(
            userId='me',
            maxResults=5
        ).execute()

        messages = results.get('messages', [])

        if not messages:

            result_text.delete(1.0, tk.END)

            result_text.insert(
                tk.END,
                "No emails found."
            )

            return

        final_report = """
====================================================
                GMAIL ANALYSIS REPORT
====================================================
"""

        for message in messages:

            msg = service.users().messages().get(
                userId='me',
                id=message['id']
            ).execute()

            payload = msg['payload']
            headers = payload.get('headers')

            subject = "Unknown"
            sender = "Unknown"

            for header in headers:

                name = header['name']

                if name == 'Subject':
                    subject = header['value']

                if name == 'From':
                    sender = header['value']

            risk_score = 0
            alerts = []

            sender_lower = sender.lower()

            suspicious_sender_keywords = [
                "verify",
                "secure",
                "update",
                "bank"
            ]

            for keyword in suspicious_sender_keywords:

                if keyword in sender_lower:

                    alerts.append(
                        f"Suspicious sender keyword: {keyword}"
                    )

                    risk_score += 20

            email_body = ""

            if 'parts' in payload:

                for part in payload['parts']:

                    data = part.get('body', {}).get('data')

                    if data:

                        decoded = base64.urlsafe_b64decode(
                            data
                        ).decode(errors="ignore")

                        email_body += decoded

            phishing_keywords = [
                "urgent",
                "verify account",
                "password",
                "click here",
                "bank"
            ]

            lower_body = email_body.lower()

            for keyword in phishing_keywords:

                if keyword in lower_body:

                    alerts.append(
                        f"Phishing keyword detected: {keyword}"
                    )

                    risk_score += 15

            url_alerts, url_score = (
                extract_urls_from_content(
                    email_body
                )
            )

            alerts.extend(url_alerts)
            risk_score += url_score

            risk_level = classify_risk(
                risk_score
            )

            recommendation = get_recommendation(
                risk_level
            )

            final_report += f"""

----------------------------------------------------
Sender         : {sender}
Subject        : {subject}

Risk Score     : {risk_score}
Risk Level     : {risk_level}

Recommendation :
{recommendation}

----------------------------------------------------
"""

            if alerts:

                for alert in alerts:
                    final_report += f"\n[!] {alert}"

            else:

                final_report += (
                    "\nNo suspicious indicators found."
                )

        final_report += (
            "\n\n===================================================="
        )

        save_log(final_report)

        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, final_report)

    except Exception as e:

        messagebox.showerror(
            "Gmail Error",
            str(e)
        )


# =====================================================
# FILE SELECTOR
# =====================================================

def select_file():

    file_path = filedialog.askopenfilename()

    if file_path:
        analyze_file(file_path)


# =====================================================
# GUI
# =====================================================

root = tk.Tk()

root.title("Threat Analyzer")

root.geometry("1100x750")


welcome_label = tk.Label(
    root,
    text=f"{get_greeting()}! Welcome to Threat Analyzer",
    font=("Arial", 18, "bold")
)

welcome_label.pack(pady=20)


description_label = tk.Label(
    root,
    text=(
        "Analyze files and Email messages for "
        "malware indicators, phishing threats, "
        "dangerous links, suspicious senders, "
        "macros, and metadata anomalies."
    ),
    font=("Arial", 11)
)

description_label.pack(pady=5)


scan_button = tk.Button(
    root,
    text="Scan File",
    font=("Arial", 14),
    command=select_file,
    width=20,
    height=2
)

scan_button.pack(pady=10)


gmail_button = tk.Button(
    root,
    text="Analyze Email",
    font=("Arial", 14),
    command=analyze_gmail,
    width=20,
    height=2
)

gmail_button.pack(pady=10)


result_text = tk.Text(
    root,
    wrap="word",
    font=("Consolas", 10)
)

result_text.pack(
    fill="both",
    expand=True,
    padx=20,
    pady=20
)

root.mainloop()
