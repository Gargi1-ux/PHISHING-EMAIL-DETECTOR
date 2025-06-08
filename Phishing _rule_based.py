import re
import sys

# List of suspicious keywords (customized)
suspicious_keywords = [
    "verify your identity", "act now", "limited time", "dear customer",
    "update your account", "payment failed", "invoice attached",
    "sensitive information", "click to unlock", "login immediately"
]

# Allowed safe domain prefix (change to your company or trusted domain)
SAFE_DOMAIN_PREFIX = "https://www.company.com"

def is_phishing(email_text):
    score = 0
    reasons = []

    # Check for suspicious keywords
    for word in suspicious_keywords:
        if word.lower() in email_text.lower():
            score += 1
            reasons.append(f"Found keyword: '{word}'")

    # Find all links
    links = re.findall(r'http[s]?://\S+', email_text)
    if links:
        score += len(links)
        reasons.append(f"Found {len(links)} link(s): {links}")

        # Check if any link domain is suspicious
        for link in links:
            if not link.startswith(SAFE_DOMAIN_PREFIX):
                reasons.append(f"Suspicious link domain: {link}")

    # Decide phishing or legit based on score threshold
    if score >= 2:
        result = "PHISHING"
    else:
        result = "LEGIT"

    return result, reasons

if __name__ == "__main__":
    # Read email content from file if provided
    if len(sys.argv) > 1:
        try:
            with open(sys.argv[1], "r", encoding="utf-8") as f:
                email = f.read()
        except FileNotFoundError:
            print(f"Error: File '{sys.argv[1]}' not found.")
            sys.exit(1)
    else:
        email = input("Paste the email content:\n\n")

    print("=== Enhanced Phishing Detector ===\n")
    result, reasons = is_phishing(email)

    print(f"\nPrediction: This email is '{result}'\n")
    print("Reasoning:")
    for reason in reasons:
        print(" -", reason)

    # Log the scan to a file
    with open("scan_log.txt", "a", encoding="utf-8") as log:
        log.write(f"\n---\nEmail:\n{email}\nResult: {result}\nReasons:\n")
        for reason in reasons:
            log.write(f" - {reason}\n")
