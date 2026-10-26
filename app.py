"""Analyze a CSV login log for suspicious authentication patterns."""
from __future__ import annotations

import csv
import io
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path

import streamlit as st

SAMPLE = """timestamp,username,source_ip,event
2026-10-27 09:00:02,alex,198.51.100.23,failed
2026-10-27 09:00:18,alex,198.51.100.23,failed
2026-10-27 09:00:39,alex,198.51.100.23,failed
2026-10-27 09:01:05,alex,198.51.100.23,failed
2026-10-27 09:01:25,alex,198.51.100.23,success
2026-10-27 09:04:10,sam,203.0.113.8,success
2026-10-27 09:10:43,admin,192.0.2.44,failed
2026-10-27 09:11:02,admin,192.0.2.44,failed
2026-10-27 09:12:15,lee,203.0.113.8,failed
"""
REQUIRED = {"timestamp", "username", "source_ip", "event"}

@dataclass
class Finding:
    severity: str
    title: str
    details: str
    source_ip: str
    username: str
    count: int


def analyze(text: str, threshold: int = 3):
    rows = list(csv.DictReader(io.StringIO(text)))
    if not rows:
        raise ValueError("The CSV file has no data rows.")
    headers = set(rows[0].keys())
    missing = REQUIRED - headers
    if missing:
        raise ValueError("Missing required CSV columns: " + ", ".join(sorted(missing)))

    failed_by_ip = Counter()
    failed_by_user_ip = Counter()
    successful_by_user_ip = set()
    for row in rows:
        event = row["event"].strip().lower()
        ip = row["source_ip"].strip()
        username = row["username"].strip()
        if event in {"failed", "failure", "login_failed"}:
            failed_by_ip[ip] += 1
            failed_by_user_ip[(ip, username)] += 1
        elif event in {"success", "succeeded", "login_success"}:
            successful_by_user_ip.add((ip, username))

    findings = []
    for (ip, username), count in sorted(failed_by_user_ip.items(), key=lambda item: (-item[1], item[0])):
        if count >= threshold:
            findings.append(Finding(
                "High" if (ip, username) in successful_by_user_ip else "Medium",
                "Repeated failed sign-ins" if (ip, username) not in successful_by_user_ip else "Repeated failures followed by a successful sign-in",
                f"{count} failed sign-in events for {username} from {ip}." + (" A successful sign-in for this account and source also appears in the log." if (ip, username) in successful_by_user_ip else ""),
                ip, username, count,
            ))
    return rows, failed_by_ip, findings


def main():
    st.set_page_config(page_title="Login Log Analyzer", page_icon="🛡️", layout="wide")
    st.title("🛡️ Login Log Analyzer")
    st.write("Review authentication logs for repeated failed sign-ins and possible account access after repeated failures.")
    st.caption("This is a defensive log-analysis demo. It does not scan networks, contact IP addresses, or identify who owns them.")

    with st.expander("CSV format and sample data", expanded=True):
        st.write("Upload a CSV with these columns: `timestamp`, `username`, `source_ip`, and `event`. Event values should be `failed` or `success`.")
        st.download_button("Download sample log", SAMPLE, "sample_auth_log.csv", "text/csv")

    upload = st.file_uploader("Choose an authentication log CSV", type=["csv"])
    if upload is None:
        st.info("Upload your own CSV, or click **Analyze sample log** to explore the example.")
        if st.button("Analyze sample log", type="primary"):
            text = SAMPLE
        else:
            return
    else:
        text = upload.getvalue().decode("utf-8-sig")

    threshold = st.slider("Flag an account and source after this many failed sign-ins", 2, 10, 3)
    try:
        rows, failed_by_ip, findings = analyze(text, threshold)
    except (ValueError, csv.Error, UnicodeDecodeError) as exc:
        st.error(str(exc))
        return

    c1, c2, c3 = st.columns(3)
    c1.metric("Log events", len(rows))
    c2.metric("Sources with failed sign-ins", len(failed_by_ip))
    c3.metric("Findings", len(findings))

    st.subheader("Findings")
    if findings:
        for f in findings:
            with st.container(border=True):
                st.markdown(f"**{f.severity}: {f.title}**")
                st.write(f.details)
                st.write("Suggested response: validate the activity with the account owner, review surrounding authentication events, and follow your organization's incident-response process. Consider MFA and rate limiting where appropriate.")
                st.caption("Behavioral mapping: repeated password attempts can resemble MITRE ATT&CK brute-force technique T1110. This is a detection hint, not proof of an attack or actor identity.")
    else:
        st.success("No repeated-failure patterns met the selected threshold.")

    st.subheader("Failed sign-ins by source")
    if failed_by_ip:
        st.bar_chart({"Failed sign-ins": dict(failed_by_ip)})
    else:
        st.write("No failed sign-ins were found in this file.")

    st.subheader("Uploaded log preview")
    st.dataframe(rows, use_container_width=True, hide_index=True)

if __name__ == "__main__":
    main()
