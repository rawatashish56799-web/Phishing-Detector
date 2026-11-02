import sys
from pathlib import Path
import joblib
from src.parser import parse_eml
from src.features import extract_features

MODEL_PATH = Path(__file__).resolve().parent.parent / "models" / "baseline.pkl"
_model = None

def _get_model():
    global _model
    if _model is None:
        _model = joblib.load(MODEL_PATH)
    return _model

# (feature, points, explanation)
RULES = [
    ("reply_mismatch", 20, "Reply-To domain differs from the From domain"),
    ("return_path_mismatch", 15, "Return-Path domain differs from the From domain"),
    ("ip_in_url", 25, "A link uses a raw IP address instead of a domain"),
    ("at_in_url", 15, "A link contains '@', which can hide the real destination"),
    ("link_text_mismatch", 25, "Visible link text does not match the real link target"),
    ("many_subdomains", 10, "A link has an unusually large number of subdomains"),
    ("long_url", 5, "A link is very long"),
    ("no_https", 5, "A link does not use HTTPS"),
    ("risky_attachment", 25, "Email has a risky attachment type"),
]

def analyze(path):
    p = parse_eml(path)
    f = extract_features(p)

    flags, rule = [], 0
    for key, pts, msg in RULES:
        if f[key]:
            rule += pts
            flags.append((msg, pts))

    if f["urgent_words"]:
        pts = min(f["urgent_words"] * 5, 20)
        rule += pts
        flags.append((f"Urgent or pressure language ({f['urgent_words']} trigger words)", pts))

    auth = p["headers"]["auth_results"].lower()
    for k in ("spf", "dkim", "dmarc"):
        if f"{k}=fail" in auth or f"{k}=softfail" in auth:
            rule += 20
            flags.append((f"{k.upper()} authentication check failed", 20))

    rule = min(rule, 100)

    text = p["headers"]["subject"] + " " + p["text"]
    ml_prob = float(_get_model().predict_proba([text])[0][1])

    risk = round(0.5 * rule + 0.5 * ml_prob * 100)
    verdict = "PHISHING" if risk >= 70 else "SUSPICIOUS" if risk >= 40 else "SAFE"

    return {
        "verdict": verdict,
        "risk_score": risk,
        "ml_probability": round(ml_prob, 3),
        "rule_score": rule,
        "red_flags": flags,
        "features": f,
        "parsed": p,
    }

if __name__ == "__main__":
    r = analyze(sys.argv[1])
    print(f"Verdict       : {r['verdict']}")
    print(f"Risk score    : {r['risk_score']}/100")
    print(f"ML probability: {r['ml_probability']}   Rule score: {r['rule_score']}")
    print("Red flags:")
    if not r["red_flags"]:
        print("  (none)")
    for msg, pts in r["red_flags"]:
        print(f"  +{pts:<3} {msg}")
