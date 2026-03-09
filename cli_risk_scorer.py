#!/usr/bin/env python3
"""
NAME
    net-risk  --  Network Anomaly Risk Scorer

SYNOPSIS
    python cli_risk_scorer.py [OPTIONS]

DESCRIPTION
    Real-time network threat detector powered by ML models trained on the
    UNSW-NB15 dataset.  Captures live network I/O statistics via psutil,
    maps them to 42 flow-level features, and outputs a binary threat
    probability (0-100%) with a colour-coded risk tier.

    The task is binary classification only:
        0  =  Normal traffic
        1  =  Anomalous / attack traffic

    Use --sample to score real flows from the UNSW-NB15 test set instead
    of live traffic (recommended for testing / demonstration).

MODELS
    rf          Random Forest          Accuracy: Best.    Load: ~2 s.
                Ensemble of 100+ trees trained on UNSW-NB15.
                Recommended for all production use cases.

    dt          Decision Tree          Accuracy: Good.    Load: Instant.
                Single tree -- fast and interpretable.

    ensemble    RF + DT (weighted)     Accuracy: Best.    Load: ~2 s.
                Averages RF (70%) + DT (30%).  Most robust against
                individual model bias.

OPTIONS
    -m MODEL, --model MODEL
                Choose model: rf | dt | ensemble
                Default: interactive selection menu is shown.

    -d, --detailed
                Print the full 42-feature breakdown after scoring,
                along with protocol, service, state, byte counts,
                packet rate, mean packet size, and threat probability.

    -s, --sample
                Score a random row from the UNSW-NB15 test CSV file
                instead of capturing live network traffic.
                Reveals the model's full 0-100% scoring range.

    -w, --watch
                Continuously score every 10 seconds.  Press Ctrl-C to stop.

    --capture-secs N
                Seconds of live traffic to capture per scan (default: 2).
                Increase for slower / lower-bandwidth interfaces.

    -h, --help
                Show this help message and exit.

RISK TIERS
     0 - 24 %   LOW RISK      Traffic appears normal.
    25 - 49 %   MEDIUM RISK   Borderline -- model is uncertain; verdict NORMAL.
    50 - 74 %   HIGH RISK     Anomalous pattern detected.
    75 - 100%   CRITICAL RISK Strong anomaly -- investigate immediately.

    Verdict flips to ANOMALOUS TRAFFIC DETECTED when probability >= 50%.

FEATURES  (42 total -- UNSW-NB15 standard feature set)

    -- Flow volume --
    dur                Duration of the network flow (seconds)
    spkts              Source -> destination packet count
    dpkts              Destination -> source packet count
    sbytes             Source -> destination byte count
    dbytes             Destination -> source byte count
    rate               Total packet rate (packets / second)

    -- TTL & load --
    sttl               Source IP time-to-live value            [HIGH importance]
    dttl               Destination IP time-to-live value       [HIGH importance]
    sload              Source bits per second                   [HIGH importance]
    dload              Destination bits per second              [HIGH importance]
    sloss              Source retransmitted / dropped packets
    dloss              Destination retransmitted / dropped packets

    -- Inter-packet timing --
    sinpkt             Mean inter-packet arrival time src->dst (ms) [HIGH]
    dinpkt             Mean inter-packet arrival time dst->src (ms) [HIGH]
    sjit               Source jitter (ms)
    djit               Destination jitter (ms)

    -- TCP window & sequence numbers --
    swin               Source TCP window advertisement size
    stcpb              Source TCP base sequence number
    dtcpb              Destination TCP base sequence number
    dwin               Destination TCP window advertisement size
    tcprtt             TCP round-trip time (seconds)
    synack             Time between SYN and SYN-ACK (seconds)
    ackdat             Time between SYN-ACK and ACK (seconds)

    -- Packet size --
    smean              Mean source payload size (bytes)         [HIGH importance]
    dmean              Mean destination payload size (bytes)    [HIGH importance]

    -- Application layer --
    trans_depth        HTTP pipelining depth (reconstructed)
    response_body_len  HTTP response body length (bytes)

    -- Connection counters (recent time-window counts) --
    ct_srv_src         Connections with same service & source IP   [HIGH]
    ct_state_ttl       Connections with same state & TTL pair      [HIGH]
    ct_dst_ltm         Connections to same destination IP
    ct_src_dport_ltm   Connections from same src IP to same dst port
    ct_dst_sport_ltm   Connections to same dst IP from same src port
    ct_dst_src_ltm     Connections between same src/dst IP pair
    ct_src_ltm         Connections from same source IP
    ct_srv_dst         Connections with same service & dest IP     [HIGH]
    is_ftp_login       1 if FTP session authenticated
    ct_ftp_cmd         Number of FTP commands in this flow
    ct_flw_http_mthd   Number of HTTP methods in this flow
    is_sm_ips_ports    1 if src/dst IPs and ports are identical

    -- Categorical --
    proto              Network protocol  (tcp / udp / ospf / ...)
    service            Application service (http / ftp / ssh / dns / -)
    state              TCP connection state  (CON / FIN / REQ / CLO / ...)

EXAMPLES
    # Interactive model menu + 2-second live capture
    python cli_risk_scorer.py

    # Random Forest, live, with full 42-feature table
    python cli_risk_scorer.py --model rf --detailed

    # Score a real UNSW-NB15 test flow (best for demos and testing)
    python cli_risk_scorer.py --model rf --sample --detailed

    # Ensemble model in sample mode
    python cli_risk_scorer.py --model ensemble --sample

    # Continuous live monitoring every 10 seconds
    python cli_risk_scorer.py --model rf --watch

    # Longer capture window for low-traffic environments
    python cli_risk_scorer.py --model rf --capture-secs 5

NOTES
    Live capture limitation:
        psutil provides system-wide aggregate I/O counters, not per-packet
        data.  Features such as sttl, dttl, sjit, tcprtt are approximated
        with fixed values (128, 64, 0, 0).  Live scores will therefore
        cluster in a similar range regardless of traffic content.
        Use --sample to see the model's full scoring range.

    No-traffic detection:
        If all byte/packet deltas are zero (e.g. WiFi disabled), the scorer
        immediately reports 0% LOW RISK without running the model.

DATASET
    UNSW-NB15 -- University of New South Wales Cyber Range Lab, 2015
    Training : 175,341 samples
    Testing  :  82,332 samples
    Label    : Binary  (0 = Normal, 1 = Attack)
"""

import argparse
import sys
import time
import os
import math
from pathlib import Path
from datetime import datetime

# ── Core dependencies ──────────────────────────────────────────────────────────
try:
    import joblib
    import numpy as np
    import pandas as pd
    import psutil
except ImportError as e:
    print(f"[ERROR] Missing dependency: {e}")
    print("Install: pip install joblib numpy pandas psutil scikit-learn")
    sys.exit(1)

# ── Rich terminal UI ───────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich import box
    from rich.rule import Rule
    from rich.align import Align
    from rich.text import Text
    from rich.columns import Columns
    RICH = True
    console = Console()
except ImportError:
    RICH = False
    console = None


# ══════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

SCRIPT_DIR   = Path(__file__).parent
DATASET_PATH = SCRIPT_DIR / "Datasets" / "UNSW_NB15_testing-set.csv"

# Available models — skipping rf_ids_model_with_feature_selection.joblib (186 MB,
# trains on a different feature set; overkill for a CLI tool).
MODELS = {
    "rf": {
        "name":     "Random Forest",
        "file":     "random_forest_ids_model.joblib",
        "emoji":    "🌲",
        "speed":    "~2 s load",
        "stars":    "★★★★★",
        "desc":     "Best accuracy — recommended for production scans",
        "color":    "green",
    },
    "dt": {
        "name":     "Decision Tree",
        "file":     "decision_tree_ids_model.joblib",
        "emoji":    "🌿",
        "speed":    "Instant",
        "stars":    "★★★★☆",
        "desc":     "Fast & interpretable — great for quick checks",
        "color":    "cyan",
    },
    "ensemble": {
        "name":     "Ensemble  (RF + DT)",
        "file":     None,           # uses rf + dt internally
        "emoji":    "🧠",
        "speed":    "~2 s load",
        "stars":    "★★★★★",
        "desc":     "Averages RF & DT probabilities — most robust",
        "color":    "yellow",
    },
}

# ── Exact feature columns the models were trained on ──────────────────────────
# (extracted from pipeline.named_steps['preprocessing'].transformers)
NUM_COLS = [
    'dur', 'spkts', 'dpkts', 'sbytes', 'dbytes', 'rate',
    'sttl', 'dttl', 'sload', 'dload', 'sloss', 'dloss',
    'sinpkt', 'dinpkt', 'sjit', 'djit',
    'swin', 'stcpb', 'dtcpb', 'dwin',
    'tcprtt', 'synack', 'ackdat',
    'smean', 'dmean', 'trans_depth', 'response_body_len',
    'ct_srv_src', 'ct_state_ttl', 'ct_dst_ltm',
    'ct_src_dport_ltm', 'ct_dst_sport_ltm', 'ct_dst_src_ltm',
    'is_ftp_login', 'ct_ftp_cmd', 'ct_flw_http_mthd',
    'ct_src_ltm', 'ct_srv_dst', 'is_sm_ips_ports',
]
CAT_COLS  = ['proto', 'service', 'state']
ALL_COLS  = NUM_COLS + CAT_COLS   # 42 features total

# ── Port → service mapping ─────────────────────────────────────────────────────
PORT_SVC = {
    80: 'http', 443: 'http', 8080: 'http', 8443: 'http',
    21: 'ftp',  20: 'ftp-data',
    22: 'ssh',
    25: 'smtp', 587: 'smtp', 465: 'smtp',
    53: 'dns',
    6667: 'irc', 6697: 'irc',
}

# ── TCP state → UNSW-NB15 state ───────────────────────────────────────────────
TCP_STATE = {
    'ESTABLISHED': 'CON',
    'TIME_WAIT':   'FIN',
    'CLOSE_WAIT':  'FIN',
    'FIN_WAIT1':   'FIN',
    'FIN_WAIT2':   'FIN',
    'LAST_ACK':    'FIN',
    'CLOSED':      'CLO',
    'LISTEN':      'REQ',
    'SYN_SENT':    'REQ',
    'SYN_RECV':    'REQ',
}

# ── Feature importance tiers (based on published RF importance for UNSW-NB15) ─
HIGH_IMP = {
    'sttl', 'dttl', 'sbytes', 'dbytes', 'sload', 'dload',
    'ct_state_ttl', 'ct_srv_src', 'ct_srv_dst', 'rate',
    'smean', 'dmean', 'sinpkt', 'dinpkt',
}
MED_IMP = {
    'proto', 'service', 'state', 'spkts', 'dpkts', 'dur',
    'response_body_len', 'trans_depth', 'ct_dst_ltm', 'ct_src_ltm',
}


# ══════════════════════════════════════════════════════════════════════════════
# MODEL LOADING
# ══════════════════════════════════════════════════════════════════════════════

def _load_one(key: str):
    """Load a single sklearn Pipeline from disk."""
    path = SCRIPT_DIR / MODELS[key]["file"]
    return joblib.load(path)


def load_models(key: str) -> dict:
    """Return a dict of loaded model(s) for the given key."""
    if not RICH:
        print(f"Loading {MODELS[key]['name']}...")
    if key == "ensemble":
        if RICH:
            with Progress(SpinnerColumn(), TextColumn("[cyan]Loading RF model..."),
                          transient=True, console=console) as p:
                p.add_task("", total=None)
                rf = _load_one("rf")
            with Progress(SpinnerColumn(), TextColumn("[cyan]Loading DT model..."),
                          transient=True, console=console) as p:
                p.add_task("", total=None)
                dt = _load_one("dt")
        else:
            rf = _load_one("rf")
            dt = _load_one("dt")
        return {"rf": rf, "dt": dt}
    else:
        if RICH:
            with Progress(SpinnerColumn(),
                          TextColumn(f"[cyan]Loading {MODELS[key]['name']}..."),
                          transient=True, console=console) as p:
                p.add_task("", total=None)
                m = _load_one(key)
        else:
            m = _load_one(key)
        return {key: m}


# ══════════════════════════════════════════════════════════════════════════════
# LIVE NETWORK FEATURE CAPTURE
# ══════════════════════════════════════════════════════════════════════════════

def _dominant(counter: dict):
    """Return key with the highest count, or None if empty."""
    return max(counter, key=counter.get) if counter else None


def capture_live(duration: float = 2.0) -> pd.DataFrame:
    """
    Capture network I/O stats over `duration` seconds via psutil.
    Maps measurements to the 42 UNSW-NB15 features the models expect.

    Notes on approximations:
    - sttl / dttl   : Windows default (128) and common remote (64)
    - sjit / djit   : Not measurable without packet timestamps → 0
    - tcprtt etc.   : Not measurable without raw socket info → 0
    - ct_* counters : Approximated from number of live connections
    """
    io1   = psutil.net_io_counters()
    conns = psutil.net_connections()
    t0    = time.time()

    time.sleep(duration)

    io2  = psutil.net_io_counters()
    t1   = time.time()
    dur  = max(t1 - t0, 0.001)

    # ── Deltas ────────────────────────────────────────────────────────────────
    bytes_tx = max(io2.bytes_sent    - io1.bytes_sent,    0)
    bytes_rx = max(io2.bytes_recv    - io1.bytes_recv,    0)
    pkts_tx  = max(io2.packets_sent  - io1.packets_sent,  0)
    pkts_rx  = max(io2.packets_recv  - io1.packets_recv,  0)
    drop_out = max(io2.dropout       - io1.dropout,       0)
    drop_in  = max(io2.dropin        - io1.dropin,        0)

    # ── No-traffic sentinel ──────────────────────────────────────────────────
    # If there is genuinely zero network I/O (e.g. WiFi/NIC disabled), feeding
    # floored fake values (1 byte, 1 packet) confuses the model into returning
    # medium risk.  Instead, return a clearly-marked empty DataFrame so the
    # caller can short-circuit scoring with 0 % / LOW RISK.
    if bytes_tx == 0 and bytes_rx == 0 and pkts_tx == 0 and pkts_rx == 0:
        empty = pd.DataFrame(columns=ALL_COLS)
        empty.attrs["no_traffic"] = True
        return empty

    spkts = max(pkts_tx, 1)
    dpkts = max(pkts_rx, 1)
    sbytes = max(bytes_tx, 1)
    dbytes = max(bytes_rx, 1)

    # ── Protocol / service / state detection ──────────────────────────────────
    tcp_c = udp_c = 0
    svc_cnt = {}
    st_cnt  = {}

    for c in conns:
        type_str = str(c.type)
        if 'STREAM' in type_str:
            tcp_c += 1
        elif 'DGRAM' in type_str:
            udp_c += 1

        for port in [c.laddr.port if c.laddr else None,
                     c.raddr.port if c.raddr else None]:
            if port and port in PORT_SVC:
                svc = PORT_SVC[port]
                svc_cnt[svc] = svc_cnt.get(svc, 0) + 1

        if c.status:
            st = TCP_STATE.get(c.status, 'CON')
            st_cnt[st] = st_cnt.get(st, 0) + 1

    proto   = 'tcp'  if tcp_c >= udp_c else 'udp'
    service = _dominant(svc_cnt) or '-'
    state   = _dominant(st_cnt)  or 'CON'
    n_conns = max(len(conns), 1)

    # ── Per-flow normalisation ─────────────────────────────────────────────────
    # UNSW-NB15 features describe a *single network flow*, not the whole machine.
    # We approximate by dividing system-wide totals by the number of active
    # connections, giving an average per-flow estimate.
    flow_pkts_tx  = max(pkts_tx  / n_conns, 1)
    flow_pkts_rx  = max(pkts_rx  / n_conns, 1)
    flow_bytes_tx = max(bytes_tx / n_conns, 1)
    flow_bytes_rx = max(bytes_rx / n_conns, 1)

    # ── Derived features ──────────────────────────────────────────────────────
    rate   = (flow_pkts_tx + flow_pkts_rx) / dur
    sload  = (flow_bytes_tx * 8) / dur           # bits per second
    dload  = (flow_bytes_rx * 8) / dur
    smean  = flow_bytes_tx / flow_pkts_tx
    dmean  = flow_bytes_rx / flow_pkts_rx
    sinpkt = (dur * 1000) / flow_pkts_tx         # ms between src packets
    dinpkt = (dur * 1000) / flow_pkts_rx

    # ── ct_* counters ─────────────────────────────────────────────────────────
    # In UNSW-NB15 these count connections within a short recent time window
    # for a particular flow's src/dst pair — typically 1–8 for normal traffic.
    # We map our active TCP connection count into that range with a log scale.
    ct_val = max(1, min(8, int(math.log2(n_conns + 1))))

    row = {
        'dur':              dur,
        'spkts':            flow_pkts_tx,
        'dpkts':            flow_pkts_rx,
        'sbytes':           flow_bytes_tx,
        'dbytes':           flow_bytes_rx,
        'rate':             rate,
        'sttl':             128,           # Windows default TTL
        'dttl':             64,            # Linux / router typical
        'sload':            sload,
        'dload':            dload,
        'sloss':            drop_out,
        'dloss':            drop_in,
        'sinpkt':           sinpkt,
        'dinpkt':           dinpkt,
        'sjit':             0.0,
        'djit':             0.0,
        'swin':             65535,         # typical TCP window size
        'stcpb':            0,
        'dtcpb':            0,
        'dwin':             65535,
        'tcprtt':           0.0,
        'synack':           0.0,
        'ackdat':           0.0,
        'smean':            smean,
        'dmean':            dmean,
        'trans_depth':      0,
        'response_body_len':0,
        'ct_srv_src':       ct_val,
        'ct_state_ttl':     min(ct_val, 4),
        'ct_dst_ltm':       ct_val,
        'ct_src_dport_ltm': 1,
        'ct_dst_sport_ltm': 1,
        'ct_dst_src_ltm':   max(1, ct_val // 2),
        'is_ftp_login':     1 if service == 'ftp' else 0,
        'ct_ftp_cmd':       0,
        'ct_flw_http_mthd': 1 if service == 'http' else 0,
        'ct_src_ltm':       ct_val,
        'ct_srv_dst':       ct_val,
        'is_sm_ips_ports':  0,
        'proto':            proto,
        'service':          service,
        'state':            state,
    }

    return pd.DataFrame([row])[ALL_COLS]



# ══════════════════════════════════════════════════════════════════════════════
# SAMPLE MODE — score a real row from the test CSV
# ══════════════════════════════════════════════════════════════════════════════

def load_sample():
    """Load a random row from the UNSW-NB15 test set."""
    df = pd.read_csv(DATASET_PATH, nrows=5000)

    # Normalise column names that differ slightly between CSV & pipeline
    rename = {
        'smeansz': 'smean', 'dmeansz': 'dmean',
        'res_bdy_len': 'response_body_len',
        'ct_src_ ltm': 'ct_src_ltm',          # note the space in raw CSV
        'sintpkt': 'sinpkt', 'dintpkt': 'dinpkt',
    }
    df.rename(columns=rename, inplace=True)
    df.columns = [c.strip().lower() for c in df.columns]

    row  = df.sample(1)
    true_label = int(row['label'].iloc[0]) if 'label' in row.columns else None

    # Keep only the 42 expected cols
    avail = [c for c in ALL_COLS if c in row.columns]
    feat  = row[avail].copy()

    # Fill anything missing with 0 / '-'
    for col in ALL_COLS:
        if col not in feat.columns:
            feat[col] = '-' if col in CAT_COLS else 0

    return feat[ALL_COLS], true_label


# ══════════════════════════════════════════════════════════════════════════════
# SCORING
# ══════════════════════════════════════════════════════════════════════════════

def score_single(model, df: pd.DataFrame, key: str = "") -> tuple:
    """(attack_prob, prediction) for one model.
    Decision Tree probabilities are capped at 0.90 to avoid the
    uncalibrated all-or-nothing output inflating scores."""
    proba = model.predict_proba(df)[0]
    pred  = int(model.predict(df)[0])
    p     = float(proba[1])
    if key == "dt":
        p = min(p, 0.90)   # cap DT's raw proba — it is not calibrated
    return p, pred


def score_models(loaded: dict, df: pd.DataFrame) -> tuple:
    """Weighted probability across all loaded models.
    If both RF and DT are present (ensemble), RF is weighted 70 % and
    DT 30 % so an uncalibrated DT cannot dominate the result."""
    scores = {k: score_single(m, df, k) for k, m in loaded.items()}
    per_model = {k: v[0] for k, v in scores.items()}

    if set(loaded.keys()) == {"rf", "dt"}:
        avg = per_model["rf"] * 0.70 + per_model["dt"] * 0.30
    else:
        avg = float(np.mean(list(per_model.values())))

    pred = 1 if avg >= 0.5 else 0
    return avg, pred, per_model


# ══════════════════════════════════════════════════════════════════════════════
# UI HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def risk_tier(p: float) -> tuple:
    """(label, color)"""
    if p < 0.25:
        return "LOW RISK",      "green"
    elif p < 0.50:
        return "MEDIUM RISK",   "yellow"
    elif p < 0.75:
        return "HIGH RISK",     "red"
    else:
        return "CRITICAL RISK", "red"


def bar(p: float, width: int = 30) -> str:
    filled = int(p * width)
    return "█" * filled + "░" * (width - filled)


def print_banner():
    if not RICH:
        print("=" * 60)
        print("  Network Anomaly Risk Scorer  |  UNSW-NB15 IDS Models")
        print("=" * 60)
        return

    console.print()
    console.print("[bold cyan]  Network Anomaly Risk Scorer[/bold cyan]")
    console.print()


def show_model_menu() -> str:
    if not RICH:
        for key, info in MODELS.items():
            print(f"  {key:<10} {info['name']:<30}")
        choice = input("\nEnter model key [rf]: ").strip()
        return choice if choice in MODELS else "rf"

    console.print()
    t = Table(box=box.ROUNDED, border_style="cyan", show_header=True,
              header_style="bold white", padding=(0, 2))
    t.add_column("#",     style="dim",      width=3)
    t.add_column("Key",   style="bold cyan", width=10)
    t.add_column("Model", style="white",     width=22)
    t.add_column("Speed", style="dim",       width=12)

    keys = list(MODELS.keys())
    for i, k in enumerate(keys, 1):
        m = MODELS[k]
        t.add_row(str(i), k, m['name'], m['speed'])

    console.print(t)
    console.print()
    choice_map = {str(i): k for i, k in enumerate(keys, 1)}
    choice_map.update({k: k for k in keys})

    raw = ""
    while raw not in choice_map:
        raw = console.input(
            "[dim]Model[/dim] (1–3 or key, default [cyan]rf[/cyan]): "
        ).strip() or "rf"
    return choice_map[raw]


def print_risk_panel(prob: float, pred: int, model_name: str,
                     mode: str, per_model: dict):
    pct           = prob * 100
    label, color  = risk_tier(prob)
    verdict       = ("[bold red]ANOMALOUS TRAFFIC DETECTED[/bold red]"
                     if pred == 1 else "[bold green]NORMAL TRAFFIC[/bold green]")

    if not RICH:
        print(f"\n{'='*50}")
        print(f"  Threat Probability : {pct:.1f}%")
        print(f"  Risk Level         : {label}")
        print(f"  Verdict            : {'ATTACK DETECTED' if pred == 1 else 'NORMAL TRAFFIC'}")
        print(f"{'='*50}\n")
        return

    console.print()
    console.print(f"  [bold]Threat Probability[/bold]  "
                  f"[bold {color}]{pct:.1f}%[/bold {color}]")
    console.print(f"  [{color}]{bar(prob)}[/{color}]  "
                  f"[{color}]{label}[/{color}]")
    console.print(f"  {verdict}")
    console.print(f"  [dim]model  {model_name}[/dim]")


def print_detailed(df: pd.DataFrame, prob: float,
                   true_label: int = None):
    if not RICH:
        print("\n--- Feature Values ---")
        for col in ALL_COLS:
            print(f"  {col:<25} {df.iloc[0][col]}")
        return

    console.print()

    # Feature table
    ft = Table(box=box.SIMPLE, border_style="dim", show_header=True,
               header_style="bold white", padding=(0, 2))
    ft.add_column("Feature",    style="cyan",  width=22)
    ft.add_column("Value",      style="white", width=18)
    ft.add_column("Importance", style="",      width=10)

    row = df.iloc[0]
    for feat in ALL_COLS:
        val = row[feat]
        if feat in HIGH_IMP:
            imp = "[red]high[/red]"
        elif feat in MED_IMP:
            imp = "[yellow]med[/yellow]"
        else:
            imp = "[dim]low[/dim]"
        val_str = f"{val:.4f}" if isinstance(val, float) else str(val)
        ft.add_row(feat, val_str, imp)

    console.print(ft)
    console.print()

    row = df.iloc[0]
    console.print(f"  Protocol   [bold]{str(row['proto']).upper()}[/bold]")
    console.print(f"  Service    {str(row['service'])}")
    console.print(f"  State      {str(row['state'])}")
    console.print(f"  Bytes Sent      {float(row['sbytes']):,.0f}")
    console.print(f"  Bytes Recv      {float(row['dbytes']):,.0f}")
    console.print(f"  Packet Rate     {float(row['rate']):.1f} pkt/s")
    console.print(f"  Mean Pkt Size   src={float(row['smean']):.0f}B  dst={float(row['dmean']):.0f}B")
    console.print(f"  Threat Prob     [bold]{prob*100:.2f}%[/bold]")

    if true_label is not None:
        lbl = "[red]ATTACK[/red]" if true_label == 1 else "[green]NORMAL[/green]"
        console.print(f"  Ground Truth    {lbl}")




# ══════════════════════════════════════════════════════════════════════════════
# CORE RUN LOGIC
# ══════════════════════════════════════════════════════════════════════════════

def run_once(model_key: str, loaded: dict, args) -> None:
    true_label = None

    # ── Acquire features ──────────────────────────────────────────────────────
    if args.sample:
        mode_label = "Test Dataset Sample"
        if RICH:
            with Progress(SpinnerColumn(),
                          TextColumn("[cyan]Loading sample from test set..."),
                          transient=True, console=console) as p:
                p.add_task("", total=None)
                feat_df, true_label = load_sample()
        else:
            feat_df, true_label = load_sample()
    else:
        secs = args.capture_secs
        mode_label = f"Live Capture ({secs:.0f}s)"
        if RICH:
            with Progress(SpinnerColumn(),
                          TextColumn(f"[cyan]Capturing {secs:.0f}s of network traffic..."),
                          transient=True, console=console) as p:
                p.add_task("", total=None)
                feat_df = capture_live(secs)
        else:
            print(f"Capturing {secs:.0f}s of network traffic...")
            feat_df = capture_live(secs)

    # ── No-traffic short-circuit ───────────────────────────────────────────────
    # capture_live() returns an empty sentinel DataFrame when there is zero
    # network I/O (e.g. WiFi disabled).  Report 0 % immediately — no inference.
    if feat_df.attrs.get("no_traffic"):
        display_name = MODELS[model_key]["name"]
        if RICH:
            console.print()
            console.print("  [bold]Threat Probability[/bold]  [bold green]0.0%[/bold green]")
            console.print(f"  [green]{bar(0.0)}[/green]  [green]LOW RISK[/green]")
            console.print("  [bold green]NORMAL TRAFFIC[/bold green]")
            console.print("  [dim]No network I/O detected — interface may be offline[/dim]")
            console.print(f"  [dim]model  {display_name}[/dim]")
            console.print()
            console.print(Rule("[dim]End of Report[/dim]"))
            console.print()
        else:
            print("\n" + "=" * 50)
            print("  Threat Probability : 0.0%")
            print("  Risk Level         : LOW RISK")
            print("  Verdict            : NORMAL TRAFFIC")
            print("  Note               : No network I/O — interface may be offline")
            print("=" * 50 + "\n")
        return

    # ── Score ──────────────────────────────────────────────────────────────────
    prob, pred, per_model = score_models(loaded, feat_df)
    display_name = MODELS[model_key]["name"]

    # ── Output ────────────────────────────────────────────────────────────────
    print_risk_panel(prob, pred, display_name, mode_label, per_model)

    if args.detailed:
        print_detailed(feat_df, prob, true_label)

    if RICH:
        console.print()
        console.print(Rule("[dim]End of Report[/dim]"))
        console.print()


# ══════════════════════════════════════════════════════════════════════════════
# CLI ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="net-risk",
        description="Network Anomaly Risk Scorer — IDS-powered threat detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "--model", "-m",
        choices=list(MODELS.keys()), default=None,
        metavar="MODEL",
        help=f"Model key: {', '.join(MODELS)} (default: interactive menu)",
    )
    p.add_argument(
        "--detailed", "-d",
        action="store_true",
        help="Show detailed feature breakdown after scoring",
    )
    p.add_argument(
        "--sample", "-s",
        action="store_true",
        help="Score from UNSW-NB15 test set (no live capture needed)",
    )
    p.add_argument(
        "--watch", "-w",
        action="store_true",
        help="Continuously monitor, print a new score every 10 s (Ctrl+C to stop)",
    )
    p.add_argument(
        "--capture-secs",
        type=float, default=2.0,
        help="Seconds of live traffic to capture (default: 2)",
    )
    return p


def main():
    parser = build_parser()
    args   = parser.parse_args()

    print_banner()

    # Model selection
    model_key = args.model or show_model_menu()
    info      = MODELS[model_key]

    if RICH:
        console.print(f"  [dim]{info['name']}[/dim]")
        console.print()

    # Load
    loaded = load_models(model_key)

    if RICH:
        console.print(f"  [green]ready[/green]\n")
    else:
        print("Model loaded.\n")

    # Run
    if args.watch:
        if RICH:
            console.print("[cyan]Monitoring mode — Ctrl+C to stop[/cyan]\n")
        try:
            while True:
                run_once(model_key, loaded, args)
                if RICH:
                    console.print("[dim]Next scan in 10 s ... (Ctrl+C to stop)[/dim]")
                time.sleep(10)
        except KeyboardInterrupt:
            msg = "\n[yellow]Monitoring stopped.[/yellow]" if RICH else "\nStopped."
            (console.print if RICH else print)(msg)
    else:
        run_once(model_key, loaded, args)


if __name__ == "__main__":
    main()
