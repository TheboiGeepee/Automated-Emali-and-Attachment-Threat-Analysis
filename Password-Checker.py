import os
import json
import string
import getpass
import hashlib
import requests
import sys
import time
import secrets
import math
from datetime import datetime

# ================= CONFIG =================
USE_API_FALLBACK = False
AUTH_FILE = "auth_data.json"

COMMON_PASSWORDS = {
    "password",
    "123456",
    "123456789",
    "qwerty",
    "abc123",
    "password1",
    "111111",
    "123123"
}

COMMON_PATTERNS = [
    "12345",
    "qwerty",
    "asdf",
    "zxcv"
]

SECURITY_QUESTIONS = [
    "What is your favorite food?",
    "What is your favorite color?",
    "What is your pet's name?",
    "What city were you born in?",
    "What is your dream car?"
]

EXIT_COMMAND = "exit"

# ================= HASH FUNCTION =================
def hash_text(text):

    return hashlib.sha256(text.encode()).hexdigest()

# ================= SAVE AUTH DATA =================
def save_auth(password, question, answer):

    data = {
        "password": hash_text(password),
        "question": question,
        "answer": hash_text(answer.lower())
    }

    with open(AUTH_FILE, "w") as f:
        json.dump(data, f)

# ================= LOAD AUTH DATA =================
def load_auth():

    if not os.path.exists(AUTH_FILE):
        return None

    with open(AUTH_FILE, "r") as f:
        return json.load(f)

# ================= FIRST TIME SETUP =================
def first_time_setup():

    print("\n\033[95m=== FIRST TIME SETUP ===\033[0m")

    while True:

        password = getpass.getpass(
            "\nCreate a master password: "
        )

        confirm = getpass.getpass(
            "Confirm password: "
        )

        if password != confirm:

            print(
                "\033[91m❌ Passwords do not match.\033[0m"
            )

            continue

        if len(password) < 8:

            print(
                "\033[91m❌ Password must be at least 8 characters.\033[0m"
            )

            continue

        break

    print("\n\033[96mChoose a security question:\033[0m\n")

    for i, q in enumerate(SECURITY_QUESTIONS, start=1):

        print(f"\033[94m{i}.\033[0m {q}")

    while True:

        try:

            choice = int(
                input("\nSelect question number: ")
            )

            if 1 <= choice <= len(SECURITY_QUESTIONS):

                question = SECURITY_QUESTIONS[choice - 1]
                break

            else:

                print(
                    "\033[91m❌ Invalid selection.\033[0m"
                )

        except ValueError:

            print(
                "\033[91m❌ Enter a valid number.\033[0m"
            )

    answer = input(f"\n{question} ").strip()

    save_auth(password, question, answer)

    print(
        "\n\033[92m✅ Account setup completed successfully!\033[0m"
    )

# ================= FORGOT PASSWORD =================
def forgot_password():

    data = load_auth()

    print("\n\033[95m=== PASSWORD RECOVERY ===\033[0m")

    answer = input(
        f"\n{data['question']} "
    ).strip().lower()

    if hash_text(answer) == data["answer"]:

        print(
            "\n\033[92m✅ Security answer verified.\033[0m"
        )

        while True:

            new_password = getpass.getpass(
                "\nEnter new password: "
            )

            confirm = getpass.getpass(
                "Confirm new password: "
            )

            if new_password != confirm:

                print(
                    "\033[91m❌ Passwords do not match.\033[0m"
                )

                continue

            if len(new_password) < 8:

                print(
                    "\033[91m❌ Password too short.\033[0m"
                )

                continue

            break

        save_auth(
            new_password,
            data["question"],
            answer
        )

        print(
            "\n\033[92m✅ Password reset successful!\033[0m"
        )

    else:

        print(
            "\n\033[91m❌ Incorrect security answer.\033[0m"
        )

# ================= LOGIN =================
def login():

    data = load_auth()

    if not data:

        first_time_setup()
        return True

    attempts = 3

    while attempts > 0:

        password = getpass.getpass(
            "\n\033[93mEnter master password: \033[0m"
        )

        if hash_text(password) == data["password"]:

            print(
                "\n\033[92m✅ Login successful!\033[0m"
            )

            return True

        attempts -= 1

        print(
            f"\033[91m❌ Incorrect password. "
            f"{attempts} attempt(s) remaining.\033[0m"
        )

    print("\n1. Try Again")
    print("2. Forgot Password")
    print("3. Exit")

    choice = input("\nChoose option: ").strip()

    if choice == "1":

        return login()

    elif choice == "2":

        forgot_password()
        return login()

    else:

        sys.exit()

# ================= ANIMATED TEXT =================
def animated_text(text, delay=0.02):

    for char in text:

        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)

    print()

# ================= CURRENT DATE & TIME =================
def show_datetime():

    now = datetime.now().astimezone()

    current_date = now.strftime("%A, %d %B %Y")
    current_time = now.strftime("%I:%M:%S %p")
    timezone = now.tzname()

    gmt_offset = now.strftime("%z")
    gmt_offset = f"GMT{gmt_offset[:3]}:{gmt_offset[3:]}"

    info = f"""
\033[95m═══════════════════════════════════════════════════════\033[0m
\033[96mCurrent Date :\033[0m {current_date}
\033[96mCurrent Time :\033[0m {current_time}
\033[96mTimezone     :\033[0m {timezone}
\033[96mGMT Offset   :\033[0m {gmt_offset}
\033[95m═══════════════════════════════════════════════════════\033[0m
"""

    animated_text(info, delay=0.003)

# ================= EXIT ANIMATION =================
def fancy_exit_with_dots(
    message="Program exited successfully. Goodbye!",
    delay=0.05,
    dots=5,
    dot_delay=0.3
):

    for _ in range(dots):

        sys.stdout.write(".")
        sys.stdout.flush()
        time.sleep(dot_delay)

    print()

    for char in message:

        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)

    print()

# ================= SAFE EXIT =================
def exit_program():

    fancy_exit_with_dots(
        "\033[91m❌ Program exited successfully. Goodbye!\033[0m"
    )

    sys.exit()

# ================= WORDLIST CHECK =================
def check_in_wordlists(password, files=("hello.txt",)):

    for filename in files:

        try:

            with open(filename, "r", encoding="latin-1") as f:

                for line in f:

                    if line.strip() == password:

                        return f"Found in {filename}"

        except FileNotFoundError:

            continue

    return None

# ================= HIBP API =================
def check_pwned_api(password):

    sha1_pwd = hashlib.sha1(
        password.encode()
    ).hexdigest().upper()

    prefix = sha1_pwd[:5]
    suffix = sha1_pwd[5:]

    url = (
        f"https://api.pwnedpasswords.com/range/{prefix}"
    )

    try:

        res = requests.get(
            url,
            timeout=5,
            verify=True
        )

        if res.status_code != 200:

            return None

        for line in res.text.splitlines():

            h, count = line.split(":")

            if h == suffix:

                return int(count)

        return 0

    except requests.RequestException:

        return None

# ================= PASSWORD ENTROPY =================
def calculate_entropy(password, charset):

    if charset == 0:

        return 0

    entropy = len(password) * math.log2(charset)

    return round(entropy, 2)

# ================= STRENGTH BAR =================
def strength_bar(
    strength,
    max_strength=4,
    length=10
):

    filled = int(
        (strength / max_strength) * length
    )

    empty = length - filled

    return (
        "[" +
        "█" * filled +
        "░" * empty +
        f"] {strength}/{max_strength}"
    )

# ================= REALISTIC CRACK TIME =================
def realistic_crack_time(
    password,
    weaknesses,
    entropy
):

    critical = [
        "Common password",
        "Found in wordlist",
        "Found in breaches"
    ]

    if any(
        cw in w
        for w in weaknesses
        for cw in critical
    ):

        return "Instantly (already exposed)"

    if entropy < 28:

        return "Less than 1 hour"

    elif entropy < 36:

        return "3 days"

    elif entropy < 60:

        return "8 months"

    elif entropy < 80:

        return "15 years"

    elif entropy < 100:

        return "247 years"

    elif entropy < 128:

        return "12,000 years"

    else:

        return "Millions of years"

# ================= PASSWORD GENERATOR =================
def generate_strong_password(length=20):

    chars = (
        string.ascii_letters +
        string.digits +
        string.punctuation
    )

    while True:

        password = ''.join(
            secrets.choice(chars)
            for _ in range(length)
        )

        if (
            any(c.islower() for c in password) and
            any(c.isupper() for c in password) and
            any(c.isdigit() for c in password) and
            any(c in string.punctuation for c in password)
        ):

            return password

# ================= PASSWORD GENERATOR MODE =================
def password_generator_mode():

    print(
        "\n\033[95m--- Password Generator ---\033[0m"
    )

    mode = input(
        "\nGenerate for Individual or Company? (i/c): "
    ).strip().lower()

    if mode == EXIT_COMMAND:

        exit_program()

    try:

        length = int(
            input(
                "\nEnter desired password length "
                "(minimum 9): "
            )
        )

        if length < 9:

            print(
                "\033[91m❌ Password length must be "
                "at least 9 characters.\033[0m"
            )

            return

        elif length < 12:

            print(
                "\033[93m⚠ Warning:\033[0m "
                "Passwords below 12 characters "
                "are less secure."
            )

    except ValueError:

        print(
            "\033[91m❌ Invalid number entered.\033[0m"
        )

        return

    if mode == "i":

        password = generate_strong_password(length)

        print(
            f"\n\033[92mGenerated Password:\033[0m\n{password}"
        )

    elif mode == "c":

        try:

            amount = int(
                input(
                    "\nHow many passwords to generate?: "
                )
            )

            if amount <= 0:

                print(
                    "\033[91m❌ Amount must be greater than 0.\033[0m"
                )

                return

            print(
                "\n\033[95m--- Generated Passwords ---\033[0m"
            )

            for i in range(amount):

                password = generate_strong_password(length)

                print(
                    f"\033[96m[{i+1}]\033[0m {password}"
                )

        except ValueError:

            print(
                "\033[91m❌ Invalid amount.\033[0m"
            )

    else:

        print(
            "\033[91m❌ Invalid option selected.\033[0m"
        )

# ================= PASSWORD CHECKER =================
def check_pwd():

    password = getpass.getpass(
        "\n\033[93mEnter Password (or type exit): \033[0m"
    )

    if password.strip().casefold() == EXIT_COMMAND:

        exit_program()

    strength = 0

    lower = upper = num = special = 0

    for c in password:

        if c in string.ascii_lowercase:

            lower += 1

        elif c in string.ascii_uppercase:

            upper += 1

        elif c in string.digits:

            num += 1

        else:

            special += 1

    if lower:
        strength += 1

    if upper:
        strength += 1

    if num:
        strength += 1

    if special:
        strength += 1

    weaknesses = []

    if password.lower() in COMMON_PASSWORDS:

        weaknesses.append("Common password")

    for pattern in COMMON_PATTERNS:

        if pattern in password.lower():

            weaknesses.append(
                f"Contains common pattern: {pattern}"
            )

            break

    if len(set(password)) <= 2:

        weaknesses.append(
            "Too many repeated characters"
        )

    if len(password) < 8:

        weaknesses.append(
            "Too short (minimum 8 characters)"
        )

    wordlist_result = check_in_wordlists(password)

    if wordlist_result:

        weaknesses.append(
            f"Found in wordlist ({wordlist_result})"
        )

        strength -= 2

    elif USE_API_FALLBACK:

        breach_count = check_pwned_api(password)

        if breach_count:

            weaknesses.append(
                f"Found in breaches {breach_count:,} times"
            )

            strength -= 2

    critical_weaknesses = [
        "Common password",
        "Found in wordlist",
        "Found in breaches"
    ]

    if any(
        cw in w
        for w in weaknesses
        for cw in critical_weaknesses
    ):

        strength = 1

    else:

        strength -= len(weaknesses)

        if strength < 1:
            strength = 1

        if strength > 4:
            strength = 4

    if strength == 1:

        remarks = "Weak Password"

    elif strength == 2:

        remarks = "Moderate Password"

    elif strength == 3:

        remarks = "Strong Password"

    else:

        remarks = "Very Strong Password"

    charset = 0

    if lower:
        charset += 26

    if upper:
        charset += 26

    if num:
        charset += 10

    if special:
        charset += 32

    entropy = calculate_entropy(password, charset)

    print(
        "\n\033[95m--- Password Analysis ---\033[0m"
    )

    print(
        f"\033[96mLowercase:\033[0m {lower}, "
        f"\033[96mUppercase:\033[0m {upper}, "
        f"\033[96mNumbers:\033[0m {num}, "
        f"\033[96mSpecial:\033[0m {special}"
    )

    print(
        f"\n\033[92mStrength:\033[0m "
        f"{strength_bar(strength)} | {remarks}"
    )

    print(
        f"\033[96mEntropy:\033[0m {entropy} bits"
    )

    if weaknesses:

        print(
            "\n\033[91m⚠️ Weaknesses detected:\033[0m"
        )

        for weakness in weaknesses:

            print(f"\033[91m-\033[0m {weakness}")

    else:

        print(
            "\n\033[92m✅ No obvious weaknesses detected\033[0m"
        )

    print(
        "\n\033[95m--- Realistic Crack Estimate ---\033[0m"
    )

    print(
        f"\033[93m"
        f"{realistic_crack_time(password, weaknesses, entropy)}"
        f"\033[0m"
    )

    del password

# ================= MAIN MENU =================
def main_menu():

    print("""
\033[95m═══════════════════════════════════\033[0m
\033[96m1.\033[0m Check Password
\033[96m2.\033[0m Generate Strong Password
\033[96m3.\033[0m Exit
\033[95m═══════════════════════════════════\033[0m
""")

    choice = input(
        "\033[94mChoose an option: \033[0m"
    ).strip()

    return choice

# ================= MAIN =================
if __name__ == "__main__":

    if not login():

        exit()

    intro = f"""
\033[96m╔════════════════════════════════════════════════════╗
║        Welcome to a Real-World Password Checker   ║
╠════════════════════════════════════════════════════╣
║  Author   : Felix Godspower                       ║
║  X        : @boiGeepee                            ║
║  Linkedin : Felix Godspower                       ║
║  Email    : geehvck@gmail.com                     ║
╚════════════════════════════════════════════════════╝\033[0m

\033[93m[ FEATURES ]\033[0m

\033[92m✔ Password Strength Analysis\033[0m
\033[92m✔ Wordlist Detection\033[0m
\033[92m✔ Breach Detection (Optional)\033[0m
\033[92m✔ Realistic Crack-Time Estimate\033[0m
\033[92m✔ Entropy Calculation\033[0m
\033[92m✔ Secure Password Generator\033[0m
\033[92m✔ Individual & Company Password Generation\033[0m
\033[92m✔ Login & Recovery System\033[0m

\033[94mStay safe and use strong passwords.\033[0m
"""

    animated_text(intro, delay=0.002)

    show_datetime()

    while True:

        option = main_menu()

        if option == "1":

            check_pwd()

        elif option == "2":

            password_generator_mode()

        elif option == "3":

            exit_program()

        elif option.strip().casefold() == EXIT_COMMAND:

            exit_program()

        else:

            print(
                "\033[91m❌ Invalid option. Please try again.\033[0m"
            )
