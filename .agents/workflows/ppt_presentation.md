# Network Anomaly Detection — PPT Presentation Workflow

---
description: How to create a PowerPoint presentation for the Network Anomaly Detection project
---

## Slide Structure

---

### Slide 1 — Title Slide
- **Title:** Network Anomaly Detection using Machine Learning
- **Subtitle:** Real-time IDS powered by UNSW-NB15 dataset
- **Content:** Project name, your name, date

---

### Slide 2 — Problem Statement
- **Title:** The Problem
- **Content:**
  - Cyber attacks are growing in volume and sophistication
  - Traditional rule-based IDS systems miss novel/unknown attacks
  - Need: An intelligent system that can detect anomalies automatically
  - Key question: *Can ML models reliably distinguish normal vs. malicious traffic?*

---

### Slide 3 — Dataset: UNSW-NB15
- **Title:** Dataset Overview — UNSW-NB15
- **Content:**
  - Created by the Australian Centre for Cyber Security (ACCS)
  - Contains real network traffic + synthetic attack scenarios
  - 49 features per flow (we use 42: 39 numerical + 3 categorical)
  - 9 attack categories: DoS, Fuzzing, Backdoor, Shellcode, Worms, etc.
  - Binary label: `0 = Normal`, `1 = Attack`
  - Files used: `UNSW_NB15_training-set.csv`, `UNSW_NB15_testing-set.csv`

---

### Slide 4 — Key Features Used
- **Title:** Feature Engineering
- **Content:**
  - **High importance (Red):** `sttl`, `dttl`, `sbytes`, `dbytes`, `rate`, `sload`, `dload`, `smean`, `dmean`, `ct_state_ttl`, `ct_srv_src`, `ct_srv_dst`, `sinpkt`, `dinpkt`
  - **Medium importance (Yellow):** `proto`, `service`, `state`, `spkts`, `dpkts`, `dur`, `response_body_len`, `trans_depth`
  - Categorical features: Protocol (`tcp`/`udp`), Service (`http`/`ftp`/`ssh`), Connection State (`CON`/`FIN`/`CLO`)

---

### Slide 5 — ML Models Trained
- **Title:** Models Used
- **Content (table format):**

| Model | Accuracy | Speed | Use Case |
|---|---|---|---|
| Random Forest | ★★★★★ Best | ~2s load | Production scans |
| Decision Tree | ★★★★☆ | Instant | Quick checks |
| Logistic Regression | ★★★☆☆ | Instant | Baseline |
| Logistic + L1 (feature selection) | ★★★☆☆ | Instant | Feature pruning |
| Ensemble (RF + DT) | ★★★★★ Most robust | ~2s load | High-confidence detection |

---

### Slide 6 — System Architecture
- **Title:** System Architecture
- **Content (diagram/flow):**
  ```
  Live Network Traffic (psutil)
         ↓
  Feature Extraction (42 UNSW-NB15 features)
         ↓
  ML Pipeline (sklearn: preprocessing → model)
         ↓
  Threat Probability Score (0–100%)
         ↓
  Risk Tier: LOW / MEDIUM / HIGH / CRITICAL
         ↓
  CLI Output (rich terminal UI)
  ```

---

### Slide 7 — CLI Tool: `cli_risk_scorer.py`
- **Title:** Real-Time Risk Scorer CLI
- **Content:**
  - Live capture mode: reads system-wide network I/O via `psutil`
  - Sample mode: scores a random row from the UNSW-NB15 test set
  - Watch mode: continuous monitoring every 10 seconds
  - Ensemble logic: RF weighted 70%, DT weighted 30%
  - Risk tiers:
    - 🟢 `< 25%` → LOW RISK
    - 🟡 `25–50%` → MEDIUM RISK
    - 🔴 `50–75%` → HIGH RISK
    - 🚨 `> 75%` → CRITICAL RISK
  - Commands:
    ```
    python cli_risk_scorer.py --model rf
    python cli_risk_scorer.py --model ensemble --detailed
    python cli_risk_scorer.py --watch
    python cli_risk_scorer.py --model rf --sample
    ```

---

### Slide 8 — Results & Performance
- **Title:** Results
- **Content:**
  - Random Forest achieved highest F1 score on UNSW-NB15 test set
  - Ensemble model balances accuracy + robustness across attack types
  - Attack categories detected: DoS, Fuzzing, Backdoor, Shellcode, Reconnaissance
  - Threat hints provided dynamically:
    - High packet rate → Possible DoS / Flooding
    - Large data transfer → Possible Exfiltration
    - FTP/SSH service → Possible Brute Force

---

### Slide 9 — Challenges & Limitations
- **Title:** Challenges & Limitations
- **Content:**
  - UNSW-NB15 represents synthetic + lab traffic — real-world traffic may differ
  - Live capture uses system-wide aggregates, not per-packet flow data
  - Some features (jitter, TCP RTT) are approximated to 0 without packet capture
  - Decision Tree probabilities are uncalibrated (capped at 90%)
  - Large model file: `random_forest_ids_model.joblib` = ~63 MB

---

### Slide 10 — Conclusion & Future Work
- **Title:** Conclusion & Future Work
- **Content:**
  - ✅ Built a fully functional IDS CLI tool trained on a real-world dataset
  - ✅ Supports 3 ML models + ensemble with weighted averaging
  - ✅ Works in live capture mode on any Windows machine via psutil
  - **Future Work:**
    - Integrate Scapy/WinPcap for true per-packet flow capture
    - Add a web dashboard (Flask/Streamlit) for visual monitoring
    - Extend to deep learning models (LSTM, Autoencoder) for temporal patterns
    - Export alerts to SIEM (Security Information and Event Management)

---

### Slide 11 — References
- **Title:** References
- **Content:**
  - Moustafa, N. & Slay, J. (2015). *UNSW-NB15: A comprehensive data set for network intrusion detection systems*. MILCIS.
  - scikit-learn documentation: https://scikit-learn.org
  - psutil documentation: https://psutil.readthedocs.io
  - UNSW ACCS Dataset: https://research.unsw.edu.au/projects/unsw-nb15-dataset

---

## Presentation Tips
- **Theme:** Use a dark/tech theme (e.g., dark blue or black background)
- **Font:** Use monospace fonts (Courier New, Consolas) for code/feature names
- **Visuals:** Add a confusion matrix screenshot, feature importance bar chart from your notebooks
- **Demo slide:** Record a short terminal GIF of `cli_risk_scorer.py --watch` and embed it
