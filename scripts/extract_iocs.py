from html.parser import HTMLParser
import argparse
import csv
import ipaddress
import re

from email import policy
from email.parser import BytesParser
from email.utils import getaddresses
from pathlib import Path
from urllib.parse import urlsplit


# Project paths
PROJECT_DIR = Path(__file__).resolve().parent.parent

# Command-line argument configuration

parser = argparse.ArgumentParser(
    description="Extract IOC indicators from an email file."
)

parser.add_argument(
    "email_file",
    nargs="?",
    default="samples/email-01.eml",
    help="Path to the .eml file to analyze"
)

args = parser.parse_args()

# Resolve the input email path
EMAIL_FILE = Path(args.email_file).expanduser()

if not EMAIL_FILE.is_absolute():
    EMAIL_FILE = PROJECT_DIR / EMAIL_FILE

EMAIL_FILE = EMAIL_FILE.resolve()

# Output configuration
OUTPUT_DIR = PROJECT_DIR / "reports"

OUTPUT_FILE = (
    OUTPUT_DIR /
    f"{EMAIL_FILE.stem}_ioc_extraction.csv"
)

# Check whether the email file exists
if not EMAIL_FILE.is_file():
    raise SystemExit(
        f"Error: Email file not found: {EMAIL_FILE}"
    )


# Parse the email file
with EMAIL_FILE.open("rb") as file:
    message = BytesParser(policy=policy.default).parse(file)


# Store extracted indicators
records = {}


def defang_domain(domain):
    """Convert a domain into a safe, non-clickable format."""
    return domain.lower().replace(".", "[.]")


def defang_email(address):
    """Defang the domain part of an email address."""
    if "@" not in address:
        return address

    local_part, domain = address.rsplit("@", 1)
    return f"{local_part}@{defang_domain(domain)}"


def add_indicator(
    indicator_type,
    value,
    evidence_location,
    context,
    notes
):
    """Add an indicator and avoid duplicate entries."""

    key = (indicator_type, value)

    if key in records:
        locations = records[key]["Evidence_Location"]

        if evidence_location not in locations:
            locations.append(evidence_location)

        return

    records[key] = {
        "Indicator_Type": indicator_type,
        "Indicator_Value_Defanged": value,
        "Evidence_Location": [evidence_location],
        "Role_or_Context": context,
        "Assessment_Status": "Unverified - Extracted",
        "Notes": notes
    }


# 1. Extract email addresses and their domains

address_headers = [
    "From",
    "To",
    "Cc",
    "Reply-To",
    "Return-Path",
    "Sender"
]

address_values = []

for header in address_headers:
    for value in message.get_all(header, []):
        address_values.append((header, str(value)))

addresses = getaddresses(
    [value for _, value in address_values]
)


for display_name, address in addresses:
    address = address.strip()

    # Skip privacy-redacted placeholder addresses
    if "redacted" in address.lower():
        continue

    if "@" not in address:
        continue

    add_indicator(
        "Email Address",
        defang_email(address),
        "Email headers",
        "Email address found in message headers",
        "Automatically extracted; not independently verified."
    )

    # Extract the email address domain
    domain = address.rsplit("@", 1)[1].lower()

    add_indicator(
        "Domain",
        defang_domain(domain),
        "Email headers",
        "Domain associated with an email address",
        "Automatically extracted; not independently verified."
    )

# Extract SMTP envelope sender from Authentication-Results
for value in message.get_all("Authentication-Results", []):

    matches = re.findall(
        r"(?i)\bsmtp\.mailfrom=([^\s;]+)",
        str(value)
    )

    for address in matches:

        if "@" not in address or "redacted" in address.lower():
            continue

        add_indicator(
            "Email Address",
            defang_email(address),
            "Authentication-Results header (smtp.mailfrom)",
            "SMTP envelope sender",
            "Automatically extracted; not independently verified."
        )

        # Extract the domain of the SMTP envelope sender
        envelope_domain = address.rsplit("@", 1)[1].lower()

        add_indicator(
            "Domain",
            defang_domain(envelope_domain),
            "Authentication-Results header (smtp.mailfrom)",
            "Domain associated with SMTP envelope sender",
            "Automatically extracted; not independently verified."
        )



# 2. Extract URLs from text and HTML body parts

url_pattern = re.compile(
    r'\bhxxps?://[^\s<>"\']+|\bhttps?://[^\s<>"\']+',
    re.IGNORECASE
)


# HTML parser for href and src attributes
class EmailHTMLParser(HTMLParser):

    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):

        for attr_name, attr_value in attrs:

            if attr_name in ("href", "src") and attr_value:
                self.links.append(
                    (attr_name, attr_value)
                )

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)


# Read email body parts
body_parts = []

for part in message.walk():

    if part.get_content_type() not in (
        "text/plain",
        "text/html"
    ):
        continue

    try:
        content = part.get_content()

    except Exception:
        payload = part.get_payload(decode=True)

        if payload is None:
            continue

        charset = part.get_content_charset() or "utf-8"

        content = payload.decode(
            charset,
            errors="replace"
        )

    if isinstance(content, str):
        body_parts.append(
            (part.get_content_type(), content)
        )


# Process and record URLs
def process_url(raw_url, evidence_location):

    url = raw_url.strip().rstrip(".,;:!?)]}")

    # Restore defanged URLs temporarily for parsing
    normalized_url = url.replace("[.]", ".")

    normalized_url = re.sub(
        r"(?i)^hxxps://",
        "https://",
        normalized_url
    )

    normalized_url = re.sub(
        r"(?i)^hxxp://",
        "http://",
        normalized_url
    )

    try:
        parsed_url = urlsplit(normalized_url)
        hostname = parsed_url.hostname

    except ValueError:
        return

    if not hostname:
        return

    if parsed_url.scheme.lower() not in ("http", "https"):
        return

    # Convert the URL back to defanged format
    safe_scheme = (
        "hxxps"
        if parsed_url.scheme.lower() == "https"
        else "hxxp"
    )

    safe_url = (
        f"{safe_scheme}://"
        f"{parsed_url.netloc.replace('.', '[.]')}"
        f"{parsed_url.path}"
    )

    if parsed_url.query:
        safe_url += f"?{parsed_url.query}"

    if parsed_url.fragment:
        safe_url += f"#{parsed_url.fragment}"

    add_indicator(
        "URL",
        safe_url,
        evidence_location,
        f"URL extracted from {evidence_location}",
        "URL was not accessed or tested."
    )

    add_indicator(
        "Hostname",
        defang_domain(hostname),
        f"Derived from {evidence_location}",
        "Hostname referenced by an embedded URL",
        "Automatically extracted; reputation not checked."
    )


# Extract URLs according to their HTML attributes
for content_type, content in body_parts:

    if content_type == "text/html":

        parser = EmailHTMLParser()
        parser.feed(content)

        for attribute, raw_url in parser.links:

            process_url(
                raw_url,
                f"HTML {attribute} attribute"
            )

    else:

        for raw_url in url_pattern.findall(content):

            process_url(
                raw_url,
                "Plain-text email body"
            )


# Extract URLs from email headers
for header in ("List-Unsubscribe",):

    for value in message.get_all(header, []):

        for raw_url in url_pattern.findall(str(value)):

            process_url(
                raw_url,
                f"{header} header"
            )


# 3. Extract IPv4 addresses from selected email headers
ip_pattern = re.compile(
    r'(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])'
)

ip_headers = [
    "Received",
    "Authentication-Results",
    "X-Sender-IP",
    "X-Originating-IP"
]

for header in ip_headers:

    for value in message.get_all(header, []):

        header_content = str(value)

        for candidate in ip_pattern.findall(header_content):

            try:
                ip = ipaddress.ip_address(candidate)

                if ip.version != 4:
                    continue

            except ValueError:
                continue

            add_indicator(
                "IPv4",
                str(ip),
                f"{header} header",
                "IP address found in email headers",
                "Automatically extracted; reputation not checked."
            )


# 4. Export results to CSV
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

fieldnames = [
    "Extraction_ID",
    "Indicator_Type",
    "Indicator_Value_Defanged",
    "Evidence_Location",
    "Role_or_Context",
    "Assessment_Status",
    "Notes"
]

with OUTPUT_FILE.open(
    "w",
    newline="",
    encoding="utf-8-sig"
) as csv_file:

    writer = csv.DictWriter(
        csv_file,
        fieldnames=fieldnames
    )

    writer.writeheader()

    for index, record in enumerate(records.values(), start=1):

        output_record = record.copy()

        output_record["Extraction_ID"] = (
            f"EXT-{index:03d}"
        )

        output_record["Evidence_Location"] = "; ".join(
            output_record["Evidence_Location"]
        )

        writer.writerow(output_record)


print("IOC extraction completed successfully.")
print(f"Indicators extracted: {len(records)}")
print(f"Output file: {OUTPUT_FILE}")
