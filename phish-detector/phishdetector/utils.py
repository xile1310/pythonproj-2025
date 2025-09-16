"""Utility helpers for the phishing detector.

Responsibilities:
- Robust text decoding and file IO for uploads
- Parsing simple email-like text into headers/body
- String and URL helpers (domains, URLs, IPv4 detection)
- Edit distance computation for lookalike checks
"""

from typing import Dict, List, Tuple  # import types for clarity on function IO
import re  # import regex for pattern matching
import os  # import os for filesystem operations

def decode_to_text(raw_bytes: bytes) -> str:
    """Decode byte content to text using UTF-8 with a latin-1 fallback."""
    try:  # try utf-8 first (strict to catch errors)
        return raw_bytes.decode("utf-8", errors="strict")  # decode as utf-8
    except UnicodeDecodeError:  # if utf-8 fails
        return raw_bytes.decode("latin-1", errors="ignore")  # fallback decode

def save_and_rename_to_txt(upload_dir: str, original_filename: str, raw_bytes: bytes) -> str:
    """Save uploaded bytes and atomically rename the file to have a .txt suffix."""
    os.makedirs(upload_dir, exist_ok=True)  # ensure directory exists
    base_name = os.path.basename(original_filename)  # safe file name
    temp_path = os.path.join(upload_dir, base_name)  # temp save path
    with open(temp_path, "wb") as f:  # open file for writing bytes
        f.write(raw_bytes)  # write uploaded bytes
    final_path = temp_path + ".txt"  # append .txt as requested
    os.replace(temp_path, final_path)  # rename file to .txt
    return final_path  # return final .txt path

def read_text_file(file_path: str) -> str:
    """Read file bytes from ``file_path`` and decode to text safely."""
    with open(file_path, "rb") as f:  # open file as bytes
        raw = f.read()  # read all bytes
    return decode_to_text(raw)  # decode robustly

def parse_email_like_text(text: str) -> Dict[str, str]:
    """Parse simple email-like text into a dict with from, subject, and body."""
    parsed: Dict[str, str] = {"from": "", "subject": "", "body": text}  # defaults
    lines = text.splitlines()  # split into lines
    for idx, line in enumerate(lines):  # scan lines
        if line.lower().startswith("from:") and parsed["from"] == "":  # From header
            parsed["from"] = line.split(":", 1)[1].strip()  # value after colon
        if line.lower().startswith("subject:") and parsed["subject"] == "":  # Subject header
            parsed["subject"] = line.split(":", 1)[1].strip()  # value after colon
        if parsed["from"] and parsed["subject"]:  # if both found
            break  # stop scanning headers
    if parsed["from"] or parsed["subject"]:  # if any header present
        for j in range(len(lines)):  # find blank separator
            if lines[j].strip() == "":  # blank line
                parsed["body"] = "\n".join(lines[j + 1:])  # rest is body
                break  # done
    return parsed  # return fields

def extract_name_and_email(from_value: str) -> Tuple[str, str]:
    """Extract display name and email from a "Name <email>" or bare email string."""
    match = re.search(r'^\s*"?([^"<]+)"?\s*<([^>]+)>\s*$', from_value)  # Name <email>
    if match:  # if matched
        return match.group(1).strip(), match.group(2).strip()  # name, email
    if "@" in from_value:  # bare email fallback
        return "", from_value.strip()  # no name, email only
    return "", ""  # none

def extract_domain(email: str) -> str:
    """Return the domain portion of an email address or an empty string."""
    return email.split("@", 1)[1].lower().strip() if "@" in email else ""  # domain or empty

def levenshtein_distance(a: str, b: str) -> int:
    """Compute Levenshtein edit distance between strings ``a`` and ``b``."""
    if a == b:  # quick exit if equal
        return 0  # zero distance
    if len(a) > len(b):  # ensure a shorter
        a, b = b, a  # swap
    previous_row = list(range(len(b) + 1))  # init row
    for i, ca in enumerate(a, start=1):  # loop over a
        current_row = [i]  # start row with index
        for j, cb in enumerate(b, start=1):  # loop over b
            insertions = previous_row[j] + 1  # cost insert
            deletions = current_row[j - 1] + 1  # cost delete
            substitutions = previous_row[j - 1] + (ca != cb)  # cost subst
            current_row.append(min(insertions, deletions, substitutions))  # choose min
        previous_row = current_row  # next iteration
    return previous_row[-1]  # final distance

def extract_urls(text: str) -> List[str]:
    """Extract a list of http(s) URLs present in ``text``."""
    return re.findall(r"https?://[^\s)\]>]+", text)  # simple url regex

def extract_domain_from_url(url: str) -> str:
    """Return the lowercase host from a URL, stripping scheme and port."""
    host_port_path = re.sub(r"^https?://", "", url).split("/", 1)[0]  # remove scheme
    host = host_port_path.split(":", 1)[0]  # drop port
    return host.lower()  # normalize

def is_ipv4_address(host: str) -> bool:
    """Return True if ``host`` is an IPv4 dotted-decimal address."""
    return re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}", host) is not None  # ipv4 dotted decimal
