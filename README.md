# Phishing Triage Toolkit
**Cyber Security Project 3 — Phishing Awareness Analysis**

A local Python command-line project that inspects supplied email/message text, identifies common phishing indicators, and recommends a triage action.

## Features
- Detects urgency, credential/payment requests, authority language, secrecy, threats, rewards, attachment prompts, MFA fatigue, and callback instructions.
- Extracts URLs and checks for URL shorteners, raw IP hosts, punycode, deep subdomains, unusual ports, and brand-like subdomain tricks.
- Optionally compares a sender display name with the sender email domain.
- Classifies messages as Safe (no strong indicators found), Suspicious, or Malicious / High Risk.
- Recommends Close, Warn User, or Block & Escalate.
- Includes sample messages and unit tests.

## Requirements
Python 3.10 or newer. No third-party packages are required.

## Structure
```text
phishing_triage_toolkit/
├── main.py
├── README.md
├── requirements.txt
├── pyproject.toml
├── .gitignore
├── phishing_triage/
│   ├── __init__.py
│   ├── analyzer.py
│   ├── headers.py
│   ├── models.py
│   ├── triage.py
│   └── urls.py
├── samples/
│   ├── suspicious_email.txt
│   └── safer_email.txt
└── tests/
    ├── __init__.py
    └── test_analyzer.py
```

## Setup
Windows:
```powershell
py -3 -m venv .venv
.venv\Scripts\activate
python main.py --help
```
macOS/Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
python main.py --help
```

## Run
```bash
python main.py --file samples/suspicious_email.txt
python main.py --text "URGENT: Verify your password at http://example.test/login"
python main.py --file samples/suspicious_email.txt --json report.json
python main.py --file samples/suspicious_email.txt --display-name "IT Support" --sender "support@example.test"
```

## Tests
```bash
python -m unittest discover -s tests -v
```

## Classification
| Score | Classification | Action |
|---:|---|---|
| 0–1 | Safe (no strong indicators found) | Close |
| 2–4 | Suspicious | Warn User |
| 5+ | Malicious / High Risk | Block & Escalate |

Scores are heuristic prioritization, not a probability or proof. A low score does not prove a message is safe.

## Safety and limitations
The tool does not fetch URLs, open attachments, contact remote services, verify DNS, validate SPF/DKIM/DMARC, or execute content. It only analyzes text supplied by the user. It is an educational prototype, not an enterprise security product. Never test a suspicious message by clicking its links or opening its attachments. Verify requests using a separate, known-good contact channel.

## Workflow
Input → Inspect text/URLs/sender details → Score indicators → Classify → Close / Warn User / Block & Escalate → Report.

## Reference to supplied training PDF
- Page 4: project goal and required phishing analysis.
- Pages 8–10: social-engineering stages, targeting, and non-email channels.
- Pages 11–17: sender spoofing, lookalike domains, header anomalies, urgency, and multi-channel lures.
- Page 18: Pause, Verify, Report.
- Page 24: Safe → Close; Suspicious → Warn User; Malicious → Block & Escalate.
