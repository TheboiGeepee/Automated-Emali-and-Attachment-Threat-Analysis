import os
import re
import hashlib
import magic
from urllib.parse import urlparse
from oletools.olevba import VBA_Parser

# ==========================================
# WELCOME SCREEN
# ==========================================

print("""
====================================================
            WELCOME TO THREAT ANALYZER
====================================================

This program was designed by Felix God'spower.

Threat Analyzer helps detect potentially malicious
files by analyzing:

- Dangerous file extensions
- Double extensions
- File type mismatches
- SHA256 hashes
- File size anomalies
- Suspicious phishing filenames
- Hidden extensions
- Embedded Office macros
- Suspicious metadata
- Malicious URLs inside files

The goal is to identify suspicious indicators
commonly used in malware and phishing attacks.

====================================================
""")


# ==========================================
# CONFIGURATION
# ==========================================

DANGEROUS_EXTENSIONS = [
    ".exe",
    ".bat",
    ".scr",
    ".js",
    ".vbs",
    ".cmd"
]

SUSPICIOUS_KEYWORDS = [
    "urgent",
    "invoice",
    "payment",
    "bank",
    "password",
    "update",
    "security",
    "payroll"
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

MIN_SIZE = 2048                 # 2 KB
MAX_SIZE = 100 * 1024 * 1024    # 100 MB

URL_REGEX = r'(https?://[^\s]+)'


# ==========================================
# SHA256 HASH GENERATION
# ==========================================

def generate_sha256(file_path):
    sha256 = hashlib.sha256()

    try:
        with open(file_path, "rb") as file:
            while chunk := file.read(4096):
                sha256.update(chunk)

        return sha256.hexdigest()

    except Exception as e:
        return f"Hash Error: {e}"


# ==========================================
# DANGEROUS EXTENSIONS
# ==========================================

def check_extension(filename):
    alerts = []

    lower_name = filename.lower()

    for ext in DANGEROUS_EXTENSIONS:
        if lower_name.endswith(ext):
            alerts.append(
                f"Dangerous extension detected: {ext}"
            )

    # Double extension check
    parts = lower_name.split(".")

    if len(parts) >= 3:
        alerts.append(
            "Suspicious double extension detected"
        )

    return alerts


# ==========================================
# FILE TYPE MISMATCH
# ==========================================

def check_file_type(file_path):
    alerts = []

    try:
        mime = magic.Magic(mime=False)
        real_type = mime.from_file(file_path)

        _, ext = os.path.splitext(file_path)
        ext = ext.lower()

        if ext in SAFE_TYPES:
            expected = SAFE_TYPES[ext]

            if expected.lower() not in real_type.lower():
                alerts.append(
                    f"File type mismatch! "
                    f"Extension says {ext} "
                    f"but actual type is '{real_type}'"
                )

        return alerts, real_type

    except Exception as e:
        return [f"Type Check Error: {e}"], "Unknown"


# ==========================================
# FILE SIZE ANALYSIS
# ==========================================

def check_file_size(file_path):
    alerts = []

    try:
        size = os.path.getsize(file_path)

        if size == 0:
            alerts.append("Empty file detected")

        elif size < MIN_SIZE:
            alerts.append(
                f"Extremely small file detected ({size} bytes)"
            )

        elif size > MAX_SIZE:
            alerts.append(
                f"Unusually large file detected ({size} bytes)"
            )

        return alerts, size

    except Exception as e:
        return [f"Size Check Error: {e}"], 0


# ==========================================
# SUSPICIOUS FILENAMES
# ==========================================

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


# ==========================================
# HIDDEN EXTENSIONS
# ==========================================

def check_hidden_extensions(filename):
    alerts = []
    score = 0

    # Example: document.pdf .exe
    if re.search(r'\.\w+\s+\.', filename):
        alerts.append(
            "Possible hidden extension trick detected"
        )
        score += 25

    # Unicode Right-To-Left Override
    if '\u202e' in filename:
        alerts.append(
            "Unicode extension spoofing detected"
        )
        score += 40

    return alerts, score


# ==========================================
# MACRO DETECTION
# ==========================================

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


# ==========================================
# METADATA INSPECTION
# ==========================================

def inspect_metadata(file_path):
    alerts = []
    score = 0

    try:
        mime = magic.Magic(mime=False)
        real_type = mime.from_file(file_path)

        suspicious_tools = [
            "AutoIt",
            "PowerShell",
            "Unknown"
        ]

        for tool in suspicious_tools:
            if tool.lower() in real_type.lower():
                alerts.append(
                    f"Suspicious creator/software detected: {tool}"
                )
                score += 20

    except Exception:
        pass

    return alerts, score


# ==========================================
# URL EXTRACTION
# ==========================================

def extract_urls(file_path):
    alerts = []
    score = 0

    suspicious_domains = [
        "bit.ly",
        "tinyurl",
        "goo.gl"
    ]

    try:
        with open(file_path, "r", errors="ignore") as file:
            content = file.read()

        urls = re.findall(URL_REGEX, content)

        for url in urls:
            alerts.append(f"URL found: {url}")

            parsed = urlparse(url)
            domain = parsed.netloc.lower()

            # URL shorteners
            for shortener in suspicious_domains:
                if shortener in domain:
                    alerts.append(
                        f"Shortened URL detected: {url}"
                    )
                    score += 25

            # Raw IP address
            if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain):
                alerts.append(
                    f"Raw IP address URL detected: {url}"
                )
                score += 30

    except Exception:
        pass

    return alerts, score


# ==========================================
# RISK CLASSIFICATION
# ==========================================

def classify_risk(score):

    if score >= 80:
        return "HIGH RISK"

    elif score >= 40:
        return "MEDIUM RISK"

    return "LOW RISK"


# ==========================================
# MAIN ANALYZER
# ==========================================

def analyze_file(file_path):

    print("\n===================================")
    print("        THREAT ANALYZER REPORT")
    print("===================================\n")

    if not os.path.exists(file_path):
        print("File does not exist.")
        return

    filename = os.path.basename(file_path)

    print(f"File Name: {filename}")

    all_alerts = []
    risk_score = 0

    # ----------------------------------
    # Extension Checks
    # ----------------------------------

    ext_alerts = check_extension(filename)

    if ext_alerts:
        risk_score += 40

    all_alerts.extend(ext_alerts)

    # ----------------------------------
    # Suspicious Filename
    # ----------------------------------

    name_alerts, name_score = (
        check_suspicious_filename(filename)
    )

    risk_score += name_score
    all_alerts.extend(name_alerts)

    # ----------------------------------
    # Hidden Extensions
    # ----------------------------------

    hidden_alerts, hidden_score = (
        check_hidden_extensions(filename)
    )

    risk_score += hidden_score
    all_alerts.extend(hidden_alerts)

    # ----------------------------------
    # File Type Check
    # ----------------------------------

    type_alerts, real_type = (
        check_file_type(file_path)
    )

    if type_alerts:
        risk_score += 50

    all_alerts.extend(type_alerts)

    # ----------------------------------
    # File Size
    # ----------------------------------

    size_alerts, size = (
        check_file_size(file_path)
    )

    all_alerts.extend(size_alerts)

    # ----------------------------------
    # SHA256
    # ----------------------------------

    sha256_hash = generate_sha256(file_path)

    # ----------------------------------
    # Macro Detection
    # ----------------------------------

    macro_alerts, macro_score = (
        check_macros(file_path)
    )

    risk_score += macro_score
    all_alerts.extend(macro_alerts)

    # ----------------------------------
    # Metadata Inspection
    # ----------------------------------

    meta_alerts, meta_score = (
        inspect_metadata(file_path)
    )

    risk_score += meta_score
    all_alerts.extend(meta_alerts)

    # ----------------------------------
    # URL Extraction
    # ----------------------------------

    url_alerts, url_score = (
        extract_urls(file_path)
    )

    risk_score += url_score
    all_alerts.extend(url_alerts)

    # ----------------------------------
    # FINAL RISK LEVEL
    # ----------------------------------

    risk_level = classify_risk(risk_score)

    # ==================================
    # DISPLAY RESULTS
    # ==================================

    print(f"Actual File Type : {real_type}")
    print(f"File Size        : {size} bytes")
    print(f"SHA256           : {sha256_hash}")

    print(f"\nRisk Score       : {risk_score}")
    print(f"Risk Level       : {risk_level}")

    print("\n----------- ANALYSIS RESULT -----------")

    if all_alerts:

        print("\nStatus: SUSPICIOUS\n")

        for alert in all_alerts:
            print(f"[!] {alert}")

    else:

        print("\nStatus: LIKELY LEGITIMATE")
        print("No suspicious indicators found.")

    print("\n===================================\n")


# ==========================================
# PROGRAM START
# ==========================================

if __name__ == "__main__":

    file_path = input(
        "Enter the file path to analyze: "
    ).strip()

    analyze_file(file_path)
