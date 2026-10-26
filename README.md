# Login Log Analyzer

A beginner Python cybersecurity project that analyzes authentication logs for repeated failed sign-ins. It helps surface patterns for a human defender to review; it does not claim to identify an attacker.

## Browser app

Install Python 3.10 or newer. In a terminal opened in this folder, run:

```bash
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

The app starts with a sample dataset you can download. Upload a CSV with the columns `timestamp`, `username`, `source_ip`, and `event` (`failed` or `success`) to analyze your own authorized logs.

## Command-line version

Run the included sample:

```bash
python main.py
```

Or provide a CSV path:

```bash
python main.py path/to/auth_log.csv
```

## What it demonstrates

- Basic log analysis and repeated-failure detection
- A possible successful sign-in after repeated failures
- A cautious behavioral mapping to MITRE ATT&CK brute-force technique T1110
- Defensive response ideas such as validating activity, reviewing surrounding events, MFA, and rate limiting

Only analyze logs you are authorized to access. The included example is synthetic. The project does not scan networks, contact addresses, or perform attacks.

For online hosting, upload `app.py`, `requirements.txt`, and optionally the other project files to a GitHub repository, then select `app.py` as the Streamlit app entry point.
