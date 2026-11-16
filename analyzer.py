import re
from .urls import analyze_urls, extract_urls

RULES = [
    ("Urgency or time pressure", r"\b(urgent|immediately|within \d+\s*(minutes?|hours?)|act now|expires today|final warning|24 hours)\b",
     "The message pressures the reader to act quickly.", 2, "high"),
    ("Credential or account-verification request", r"\b(verify (your )?(account|password|identity)|confirm (your )?(password|login)|reset your password|sign in to avoid|account will be (locked|suspended))\b",
     "The message asks for account verification or credentials.", 3, "high"),
    ("Payment or financial request", r"\b(wire transfer|payment failed|pay now|bank details|gift card|invoice overdue|update billing|transfer funds)\b",
     "The message requests money, payment details, or a financial action.", 3, "high"),
    ("Authority impersonation language", r"\b(ceo|chief executive|it department|it support|administrator|security team|human resources|government agency)\b",
     "The message invokes an authority role; verify unexpected instructions independently.", 1, "low"),
    ("Secrecy or bypass request", r"\b(strictly confidential|do not tell|don't tell|keep this secret|bypass (the )?(usual|standard) procedure|do not discuss)\b",
     "The message discourages normal review or asks the recipient to bypass procedure.", 3, "high"),
    ("Threat or fear language", r"\b(legal action|account terminated|permanently deleted|penalty|arrest|suspended immediately)\b",
     "The message uses threats or fear to influence a decision.", 2, "medium"),
    ("Prize or reward lure", r"\b(you have won|claim your prize|free reward|unexpected prize|lottery winner)\b",
     "The message uses an unexpected reward as a lure.", 2, "medium"),
    ("Suspicious attachment reference", r"\b(open|enable|download|review) (the )?(attached|attachment|document|invoice|html file|zip file)\b",
     "The message encourages opening or enabling an attachment.", 2, "medium"),
    ("MFA fatigue or repeated approval", r"\b(approve the sign.?in|approve the request|multiple authentication|mfa request|push notification)\b",
     "The message refers to an authentication approval that should be verified carefully.", 2, "medium"),
    ("Callback-only contact instruction", r"\b(call (this|the) number|contact support at|call support immediately)\b",
     "The message directs the recipient to a supplied phone number; find the official number independently.", 2, "medium"),
]


def analyze_message(text):
    indicators = []
    for name, pattern, explanation, points, severity in RULES:
        if re.search(pattern, text, flags=re.IGNORECASE):
            indicators.append({
                "name": name,
                "explanation": explanation,
                "points": points,
                "severity": severity,
            })
    indicators.extend(analyze_urls(text))
    return {
        "score": sum(item["points"] for item in indicators),
        "indicators": indicators,
        "urls_found": extract_urls(text),
    }
