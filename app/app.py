import sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import streamlit as st
from src.analyze import analyze

st.set_page_config(page_title="Phishing Email Analyzer", layout="wide")
st.title("Phishing Email Detection and Analysis")
st.caption("Upload an .eml file. A text ML model is combined with header and link checks to give a risk score.")

samples = sorted((ROOT / "samples").glob("*.eml"))
source = st.radio("Input", ["Upload .eml", "Use a sample"], horizontal=True)

path = None
if source == "Upload .eml":
    up = st.file_uploader("Choose an .eml file", type="eml")
    if up:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".eml") as t:
            t.write(up.read())
            path = t.name
else:
    if samples:
        choice = st.selectbox("Sample email", [s.name for s in samples])
        path = str(ROOT / "samples" / choice)
    else:
        st.info("No sample files found in the samples/ folder.")

if path:
    try:
        r = analyze(path)
    except Exception as e:
        st.error(f"Could not analyze this file: {e}")
        st.stop()

    verdict, risk = r["verdict"], r["risk_score"]
    if verdict == "PHISHING":
        st.error(f"Verdict: {verdict}")
    elif verdict == "SUSPICIOUS":
        st.warning(f"Verdict: {verdict}")
    else:
        st.success(f"Verdict: {verdict}")

    c1, c2, c3 = st.columns(3)
    c1.metric("Risk score", f"{risk}/100")
    c2.metric("ML phishing probability", r["ml_probability"])
    c3.metric("Rule-based score", f"{r['rule_score']}/100")
    st.progress(min(risk, 100) / 100)

    st.subheader("Red flags")
    if r["red_flags"]:
        st.table({"Red flag": [m for m, _ in r["red_flags"]],
                  "Points": [p for _, p in r["red_flags"]]})
    else:
        st.write("No red flags found.")

    p = r["parsed"]
    left, right = st.columns(2)
    with left:
        st.subheader("Header analysis")
        st.json(p["headers"])
        st.subheader("Attachments")
        st.write(p["attachments"] if p["attachments"] else "None")
    with right:
        st.subheader("Links found")
        if p["links"]:
            for shown, href in p["links"]:
                st.markdown(f"Shown as: `{shown or '(no text)'}`")
                st.markdown(f"Really goes to: `{href}`")
                st.divider()
        for u in p["urls"]:
            st.code(u)
        if not p["urls"]:
            st.write("No links found.")

    with st.expander("All extracted features"):
        st.json(r["features"])
