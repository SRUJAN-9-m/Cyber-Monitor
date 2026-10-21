"""
CyberMonitor – A beginner-friendly cybersecurity dashboard built with Streamlit.
Drop-in Splunk alternative for local Windows Security Event log analysis.
"""

import random
import io
from datetime import datetime, timedelta

import pandas as pd
import streamlit as st
import altair as alt

# ─────────────────────────────────────────────
#  Page config (MUST be first Streamlit call)
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="CyberMonitor",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────
#  Dark-theme CSS injection
# ─────────────────────────────────────────────
DARK_CSS = """
<style>
/* ── Global ── */
html, body, [data-testid="stAppViewContainer"] {
    background-color: #0d1117;
    color: #e6edf3;
    font-family: "Segoe UI", system-ui, sans-serif;
}
[data-testid="stSidebar"] {
    background-color: #161b22;
    border-right: 1px solid #30363d;
}
[data-testid="stSidebar"] * { color: #c9d1d9 !important; }

/* ── Top header bar ── */
.top-bar {
    background: linear-gradient(90deg, #1f6feb 0%, #388bfd 100%);
    border-radius: 10px;
    padding: 18px 28px;
    margin-bottom: 24px;
    display: flex;
    align-items: center;
    gap: 14px;
}
.top-bar h1 { margin: 0; font-size: 1.8rem; color: #ffffff; letter-spacing: 1px; }
.top-bar p  { margin: 0; color: #cfe2ff; font-size: 0.85rem; }

/* ── KPI cards ── */
.kpi-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin-bottom: 28px;
}
.kpi-card {
    background: #161b22;
    border: 1px solid #30363d;
    border-radius: 10px;
    padding: 20px 22px;
    text-align: center;
}
.kpi-card .kpi-label {
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 1.2px;
    color: #8b949e;
    margin-bottom: 8px;
}
.kpi-card .kpi-value {
    font-size: 2rem;
    font-weight: 700;
    color: #e6edf3;
    line-height: 1;
}
.kpi-card .kpi-icon { font-size: 1.6rem; margin-bottom: 6px; }
.kpi-total   { border-top: 3px solid #388bfd; }
.kpi-fail    { border-top: 3px solid #f85149; }
.kpi-success { border-top: 3px solid #3fb950; }
.kpi-priv    { border-top: 3px solid #d29922; }

/* ── Section headers ── */
.section-title {
    font-size: 0.85rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #8b949e;
    border-bottom: 1px solid #30363d;
    padding-bottom: 6px;
    margin-bottom: 14px;
}

/* ── Data table ── */
[data-testid="stDataFrame"] table {
    background-color: #161b22 !important;
    color: #e6edf3 !important;
}
[data-testid="stDataFrame"] th {
    background-color: #21262d !important;
    color: #8b949e !important;
    font-size: 0.75rem !important;
    text-transform: uppercase;
    letter-spacing: 0.8px;
}
[data-testid="stDataFrame"] td { border-color: #30363d !important; }

/* ── Streamlit widget overrides ── */
.stSelectbox label, .stMultiSelect label, .stFileUploader label {
    color: #8b949e !important;
    font-size: 0.8rem !important;
    text-transform: uppercase;
    letter-spacing: 0.8px;
}
div[data-baseweb="select"] > div {
    background-color: #21262d !important;
    border-color: #30363d !important;
    color: #e6edf3 !important;
}
div[data-baseweb="tag"] { background-color: #1f6feb !important; }

/* ── Severity badge colours in table rows ── */
</style>
"""
st.markdown(DARK_CSS, unsafe_allow_html=True)

# ─────────────────────────────────────────────
#  Mock data generator
# ─────────────────────────────────────────────
ACCOUNTS   = ["SYSTEM", "jsmith", "adavis", "mkumar", "svc_backup", "NETWORK SERVICE", "lzhang"]
COMPUTERS  = ["DESKTOP-WIN11", "SRV-DC01", "SRV-FILE02", "LAPTOP-HR", "SRV-EXCHANGE"]
SEVERITIES = ["Information", "Warning", "Critical", "Error"]

EVENT_CATALOG = {
    4624: ("Successful Logon",       "Information"),
    4625: ("Failed Logon",           "Critical"),
    4648: ("Logon with Explicit Credentials", "Warning"),
    4672: ("Special Privileges Assigned",     "Warning"),
    4688: ("New Process Created",    "Information"),
    4698: ("Scheduled Task Created", "Warning"),
    4720: ("User Account Created",   "Information"),
    4732: ("Member Added to Group",  "Warning"),
    4756: ("Member Added to Universal Group", "Warning"),
    4771: ("Kerberos Pre-Auth Failed",        "Error"),
}

def generate_mock_data(n: int = 500) -> pd.DataFrame:
    """Return a DataFrame that mimics a Windows Security Event log export."""
    random.seed(42)
    event_ids = list(EVENT_CATALOG.keys())
    weights   = [30, 20, 5, 10, 12, 4, 5, 5, 4, 5]   # realistic distribution

    now = datetime.now()
    records = []
    for _ in range(n):
        eid   = random.choices(event_ids, weights=weights, k=1)[0]
        label, default_sev = EVENT_CATALOG[eid]
        ts    = now - timedelta(minutes=random.randint(0, 60 * 24 * 7))
        records.append({
            "TimeGenerated": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "EventID":       eid,
            "Level":         default_sev,
            "Message":       label,
            "Account":       random.choice(ACCOUNTS),
            "Computer":      random.choice(COMPUTERS),
            "Source":        "Microsoft-Windows-Security-Auditing",
        })

    df = pd.DataFrame(records).sort_values("TimeGenerated", ascending=False).reset_index(drop=True)
    return df


# ─────────────────────────────────────────────
#  CSV / log file parser
# ─────────────────────────────────────────────
REQUIRED_COLS = {"TimeGenerated", "EventID"}

COLUMN_ALIASES = {
    "timecreated":    "TimeGenerated",
    "time created":   "TimeGenerated",
    "timestamp":      "TimeGenerated",
    "date":           "TimeGenerated",
    "eventid":        "EventID",
    "event id":       "EventID",
    "event_id":       "EventID",
    "id":             "EventID",
    "leveldisplayname": "Level",
    "level":          "Level",
    "severity":       "Level",
    "message":        "Message",
    "taskcategoryname": "Message",
    "accountname":    "Account",
    "account name":   "Account",
    "account":        "Account",
    "computername":   "Computer",
    "computer name":  "Computer",
    "computer":       "Computer",
    "providername":   "Source",
    "source":         "Source",
    "logname":        "Source",
}

def normalise_columns(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [c.strip() for c in df.columns]
    rename_map = {c: COLUMN_ALIASES[c.lower()] for c in df.columns if c.lower() in COLUMN_ALIASES}
    df = df.rename(columns=rename_map)
    for col in ["Level", "Message", "Account", "Computer", "Source"]:
        if col not in df.columns:
            df[col] = "N/A"
    df["EventID"] = pd.to_numeric(df["EventID"], errors="coerce").fillna(0).astype(int)
    return df

def load_uploaded_file(uploaded) -> pd.DataFrame:
    raw = uploaded.read()
    try:
        df = pd.read_csv(io.BytesIO(raw))
    except Exception:
        lines = raw.decode("utf-8", errors="replace").splitlines()
        records = [{"TimeGenerated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "EventID": 0, "Level": "Information",
                    "Message": l, "Account": "N/A",
                    "Computer": "N/A", "Source": "Custom"}
                   for l in lines if l.strip()]
        df = pd.DataFrame(records)
    df = normalise_columns(df)
    missing = REQUIRED_COLS - set(df.columns)
    if missing:
        st.sidebar.error(f"File is missing required columns: {missing}")
        return pd.DataFrame()
    return df


# ─────────────────────────────────────────────
#  Sidebar
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("## 🛡️ CyberMonitor")
    st.markdown("---")

    st.markdown("### 📂 Log Source")
    uploaded_file = st.file_uploader(
        "Upload .csv or .log file",
        type=["csv", "log"],
        help="Export from Windows Event Viewer or any compatible source.",
    )

    st.markdown("---")
    st.markdown("### 🔍 Filters")


# ─────────────────────────────────────────────
#  Data loading
# ─────────────────────────────────────────────
if uploaded_file is not None:
    df = load_uploaded_file(uploaded_file)
    data_source_label = f"📄 {uploaded_file.name}"
    if df.empty:
        st.warning("Could not parse the uploaded file. Falling back to mock data.")
        df = generate_mock_data()
        data_source_label = "⚙️ Mock Data (fallback)"
else:
    df = generate_mock_data()
    data_source_label = "⚙️ Mock Data (demo mode)"

df["TimeGenerated"] = pd.to_datetime(df["TimeGenerated"], errors="coerce")
df = df.dropna(subset=["TimeGenerated"]).reset_index(drop=True)


# ─────────────────────────────────────────────
#  Sidebar filters (rendered after data load)
# ─────────────────────────────────────────────
with st.sidebar:
    unique_eids = sorted(df["EventID"].unique().tolist())
    selected_eids = st.multiselect(
        "Event ID",
        options=unique_eids,
        default=[],
        placeholder="All event IDs",
    )

    unique_levels = sorted(df["Level"].unique().tolist())
    selected_levels = st.multiselect(
        "Severity / Level",
        options=unique_levels,
        default=[],
        placeholder="All severities",
    )

    unique_accounts = sorted(df["Account"].unique().tolist())
    selected_accounts = st.multiselect(
        "Source Account",
        options=unique_accounts,
        default=[],
        placeholder="All accounts",
    )

    st.markdown("---")
    st.markdown(
        f"<small style='color:#8b949e'>Data source:<br>{data_source_label}</small>",
        unsafe_allow_html=True,
    )

# Apply filters
filtered = df.copy()
if selected_eids:
    filtered = filtered[filtered["EventID"].isin(selected_eids)]
if selected_levels:
    filtered = filtered[filtered["Level"].isin(selected_levels)]
if selected_accounts:
    filtered = filtered[filtered["Account"].isin(selected_accounts)]


# ─────────────────────────────────────────────
#  Header bar
# ─────────────────────────────────────────────
st.markdown("""
<div class="top-bar">
  <span style="font-size:2rem">🛡️</span>
  <div>
    <h1>CyberMonitor</h1>
    <p>Real-time Windows Security Event Log Analysis · Beginner-Friendly Splunk Alternative</p>
  </div>
</div>
""", unsafe_allow_html=True)


# ─────────────────────────────────────────────
#  KPI Cards
# ─────────────────────────────────────────────
total_events      = len(filtered)
failed_logins     = len(filtered[filtered["EventID"] == 4625])
successful_logins = len(filtered[filtered["EventID"] == 4624])
priv_escalations  = len(filtered[filtered["EventID"] == 4672])

kpi_html = f"""
<div class="kpi-grid">
  <div class="kpi-card kpi-total">
    <div class="kpi-icon">📊</div>
    <div class="kpi-label">Total Events</div>
    <div class="kpi-value">{total_events:,}</div>
  </div>
  <div class="kpi-card kpi-fail">
    <div class="kpi-icon">🚫</div>
    <div class="kpi-label">Failed Logins (4625)</div>
    <div class="kpi-value">{failed_logins:,}</div>
  </div>
  <div class="kpi-card kpi-success">
    <div class="kpi-icon">✅</div>
    <div class="kpi-label">Successful Logins (4624)</div>
    <div class="kpi-value">{successful_logins:,}</div>
  </div>
  <div class="kpi-card kpi-priv">
    <div class="kpi-icon">⚠️</div>
    <div class="kpi-label">Privilege Escalations (4672)</div>
    <div class="kpi-value">{priv_escalations:,}</div>
  </div>
</div>
"""
st.markdown(kpi_html, unsafe_allow_html=True)


# ─────────────────────────────────────────────
#  Chart — Event Volume Over Time
# ─────────────────────────────────────────────
st.markdown('<div class="section-title">📈 Event Volume Over Time</div>', unsafe_allow_html=True)

if not filtered.empty:
    chart_df = (
        filtered.set_index("TimeGenerated")
        .resample("1h")
        .size()
        .reset_index(name="Count")
        .rename(columns={"TimeGenerated": "Hour"})
    )

    # Severity breakdown for colour
    sev_df = (
        filtered.groupby([pd.Grouper(key="TimeGenerated", freq="1h"), "Level"])
        .size()
        .reset_index(name="Count")
        .rename(columns={"TimeGenerated": "Hour"})
    )

    SEV_COLORS = {
        "Critical":    "#f85149",
        "Error":       "#ff7b72",
        "Warning":     "#d29922",
        "Information": "#388bfd",
    }
    domain = list(SEV_COLORS.keys())
    range_ = [SEV_COLORS.get(k, "#8b949e") for k in domain]

    chart = (
        alt.Chart(sev_df)
        .mark_area(opacity=0.75, interpolate="monotone")
        .encode(
            x=alt.X("Hour:T", title="Time", axis=alt.Axis(labelColor="#8b949e", titleColor="#8b949e", gridColor="#21262d")),
            y=alt.Y("Count:Q", title="Events", stack=True, axis=alt.Axis(labelColor="#8b949e", titleColor="#8b949e", gridColor="#21262d")),
            color=alt.Color(
                "Level:N",
                scale=alt.Scale(domain=domain, range=range_),
                legend=alt.Legend(labelColor="#c9d1d9", titleColor="#8b949e", orient="top-right"),
            ),
            tooltip=["Hour:T", "Level:N", "Count:Q"],
        )
        .properties(height=260)
        .configure_view(strokeWidth=0, fill="#0d1117")
        .configure(background="#0d1117")
    )
    st.altair_chart(chart, use_container_width=True)
else:
    st.info("No events match the current filters.")


# ─────────────────────────────────────────────
#  Data Table
# ─────────────────────────────────────────────
st.markdown('<div class="section-title">🗂️ Event Log Table</div>', unsafe_allow_html=True)

display_cols = [c for c in ["TimeGenerated", "EventID", "Level", "Message", "Account", "Computer", "Source"] if c in filtered.columns]
table_df = filtered[display_cols].copy()
table_df["TimeGenerated"] = table_df["TimeGenerated"].dt.strftime("%Y-%m-%d %H:%M:%S")

MAX_ROWS = 500
if len(table_df) > MAX_ROWS:
    st.caption(f"Showing first {MAX_ROWS:,} of {len(table_df):,} matching events.")
    table_df = table_df.head(MAX_ROWS)

st.dataframe(
    table_df,
    use_container_width=True,
    height=420,
    column_config={
        "EventID":  st.column_config.NumberColumn("Event ID", format="%d"),
        "Level":    st.column_config.TextColumn("Severity"),
        "Message":  st.column_config.TextColumn("Description"),
        "Account":  st.column_config.TextColumn("Account"),
        "Computer": st.column_config.TextColumn("Computer"),
        "Source":   st.column_config.TextColumn("Source"),
    },
    hide_index=True,
)


# ─────────────────────────────────────────────
#  Top Offenders
# ─────────────────────────────────────────────
col_a, col_b = st.columns(2)

with col_a:
    st.markdown('<div class="section-title">🏆 Top Accounts by Event Count</div>', unsafe_allow_html=True)
    if not filtered.empty:
        top_accounts = filtered["Account"].value_counts().head(8).reset_index()
        top_accounts.columns = ["Account", "Events"]
        bar_acc = (
            alt.Chart(top_accounts)
            .mark_bar(color="#388bfd", cornerRadiusTopLeft=4, cornerRadiusTopRight=4)
            .encode(
                x=alt.X("Events:Q", axis=alt.Axis(labelColor="#8b949e", titleColor="#8b949e", gridColor="#21262d")),
                y=alt.Y("Account:N", sort="-x", axis=alt.Axis(labelColor="#c9d1d9", titleColor="#8b949e")),
                tooltip=["Account:N", "Events:Q"],
            )
            .properties(height=240)
            .configure_view(strokeWidth=0, fill="#161b22")
            .configure(background="#161b22")
        )
        st.altair_chart(bar_acc, use_container_width=True)

with col_b:
    st.markdown('<div class="section-title">📋 Event ID Breakdown</div>', unsafe_allow_html=True)
    if not filtered.empty:
        eid_counts = filtered["EventID"].value_counts().head(8).reset_index()
        eid_counts.columns = ["EventID", "Count"]
        eid_counts["Label"] = eid_counts["EventID"].astype(str)

        pie = (
            alt.Chart(eid_counts)
            .mark_arc(innerRadius=55, padAngle=0.02)
            .encode(
                theta=alt.Theta("Count:Q"),
                color=alt.Color(
                    "Label:N",
                    scale=alt.Scale(scheme="tableau10"),
                    legend=alt.Legend(labelColor="#c9d1d9", titleColor="#8b949e", orient="right"),
                ),
                tooltip=["Label:N", "Count:Q"],
            )
            .properties(height=240)
            .configure_view(strokeWidth=0, fill="#161b22")
            .configure(background="#161b22")
        )
        st.altair_chart(pie, use_container_width=True)


# ─────────────────────────────────────────────
#  Footer
# ─────────────────────────────────────────────
st.markdown("""
<hr style="border-color:#30363d; margin-top:40px">
<p style="text-align:center; color:#8b949e; font-size:0.75rem">
  🛡️ CyberMonitor &nbsp;|&nbsp; Built with Python &amp; Streamlit &nbsp;|&nbsp;
  For educational &amp; internal monitoring use only
</p>
""", unsafe_allow_html=True)