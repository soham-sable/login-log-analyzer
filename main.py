"""Command-line companion for the login log analyzer."""
import csv
import sys
from collections import Counter
from pathlib import Path

REQUIRED = {"timestamp", "username", "source_ip", "event"}

def analyze(path, threshold=3):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        reader = csv.DictReader(handle)
        missing = REQUIRED - set(reader.fieldnames or [])
        if missing:
            raise ValueError("Missing CSV columns: " + ", ".join(sorted(missing)))
        rows = list(reader)
    failed = Counter()
    succeeded = set()
    for row in rows:
        key = (row["source_ip"].strip(), row["username"].strip())
        event = row["event"].strip().lower()
        if event in {"failed", "failure", "login_failed"}:
            failed[key] += 1
        elif event in {"success", "succeeded", "login_success"}:
            succeeded.add(key)
    print(f"Analyzed {len(rows)} events.\n")
    findings = 0
    for (ip, username), count in failed.most_common():
        if count >= threshold:
            findings += 1
            status = "HIGH: followed by successful sign-in" if (ip, username) in succeeded else "MEDIUM: repeated failures"
            print(f"{status} — user={username}, source={ip}, failed attempts={count}")
    if not findings:
        print("No repeated-failure patterns met the threshold.")
    else:
        print("\nReview surrounding events and follow your organization's incident-response process.")

if __name__ == "__main__":
    file_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).with_name("sample_auth_log.csv")
    try:
        analyze(file_path)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}")
        raise SystemExit(1)
