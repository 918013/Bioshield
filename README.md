# BioShield

I built this after learning about Artificial Immune Systems — a field where biological immune processes are modelled computationally. The idea stuck with me: your immune system never studies diseases. It just learns your own body so well that anything foreign gets attacked automatically.

That's a fundamentally different approach to security than what most systems use.

---

## What it does

Takes network connection parameters as input and classifies them as normal traffic or a potential attack — using an anomaly detection model trained on 125,973 real connections from the NSL-KDD cybersecurity dataset.

The interface runs in the browser. Input values, click analyse, get a result.

---

## How it works

The model learns the pattern of normal traffic. Anything that deviates significantly gets flagged. No list of known attacks needed — just a strong understanding of what normal looks like.

This mirrors how T-cells are trained in the thymus gland: cells that react to the body's own tissue are eliminated. Only cells that ignore normal tissue survive — and those are the ones that patrol for threats.

---

## Stack

Python, Flask, Scikit-learn, Pandas

---

## To run

```bash
pip install flask pandas scikit-learn numpy matplotlib
python app.py
```

---

Baseline accuracy is 57% with 94% recall on normal traffic. The model has clear room for improvement — better contamination tuning and replacing IsolationForest with a proper Negative Selection implementation would be the next steps.

