import argparse
import json
from pathlib import Path

from phishing_triage.analyzer import analyze_message
from phishing_triage.headers import analyze_sender
from phishing_triage.triage import build_report


def main():
    parser = argparse.ArgumentParser(
        description="Analyze email/message text for common phishing indicators."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", help="UTF-8 text file containing the message.")
    source.add_argument("--text", help="Message text to analyze directly.")
    parser.add_argument("--display-name", default="", help="Optional sender display name.")
    parser.add_argument("--sender", default="", help="Optional sender email address.")
    parser.add_argument("--json", dest="json_path", help="Optional JSON report output path.")
    args = parser.parse_args()

    try:
        message = Path(args.file).read_text(encoding="utf-8") if args.file else args.text
    except (OSError, UnicodeError) as exc:
        parser.error(f"Could not read input file: {exc}")

    result = analyze_message(message)
    result["indicators"].extend(analyze_sender(args.display_name, args.sender))
    result["score"] = sum(item["points"] for item in result["indicators"])
    report = build_report(result)

    print("=" * 60)
    print("PHISHING TRIAGE REPORT")
    print("=" * 60)
    print(f"Classification : {report['classification']}")
    print(f"Risk score     : {report['score']}")
    print(f"Recommended    : {report['action']}")
    print("\\nDetected indicators:")
    if not report["indicators"]:
        print("  No configured indicators were detected.")
    for item in report["indicators"]:
        print(f"  [{item['severity'].upper()}] {item['name']} (+{item['points']})")
        print(f"      {item['explanation']}")
    print("\\nNext steps:")
    for step in report["next_steps"]:
        print(f"  - {step}")
    print("\\nNote: heuristic analysis only; a low score does not prove safety.")

    if args.json_path:
        Path(args.json_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\\nJSON report saved to: {args.json_path}")


if __name__ == "__main__":
    main()
