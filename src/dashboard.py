"""
================================================================================
FUTURISTIC SOC DASHBOARD - Log Hunting Tool
================================================================================
Run with: streamlit run src/dashboard.py
================================================================================
"""

from __future__ import annotations

from datetime import datetime
import ipaddress
from pathlib import Path
import re

import altair as alt
import pandas as pd
import pydeck as pdk
import streamlit as st

from analyzer import DetectionConfig, ThreatAnalyzer
from parser import LogParser


APP_ROOT = Path(__file__).resolve().parents[1]


DEFAULT_LOG_FILES = {
    "auth": "sample_logs/auth.log",
    "ssh": "sample_logs/ssh.log",
    "web": "sample_logs/web.log",
    "router": "sample_logs/router.log",
}


st.set_page_config(
    page_title="NEON SIEM | SOC Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


STYLES = """
<style>
:root {
    --bg-main: #050b1a;
    --bg-panel: rgba(16, 28, 56, 0.55);
    --bg-panel-soft: rgba(20, 36, 71, 0.42);
    --line: rgba(93, 151, 255, 0.35);
    --blue: #49b3ff;
    --blue-neon: #38d7ff;
    --orange: #ff9a3d;
    --orange-neon: #ffb347;
    --danger: #ff4966;
    --text: #d9eeff;
    --muted: #8ca6c9;
}

.stApp {
    background:
        radial-gradient(circle at 20% 20%, rgba(56, 112, 255, 0.15), transparent 40%),
        radial-gradient(circle at 80% 10%, rgba(255, 129, 56, 0.12), transparent 38%),
        linear-gradient(140deg, #02050f 0%, #071329 40%, #030818 100%);
    color: var(--text);
}

.block-container {
    max-width: 1920px;
    padding-top: 1.2rem;
    padding-bottom: 1rem;
}

h1, h2, h3, h4, h5, h6 {
    color: var(--text) !important;
    letter-spacing: 0.2px;
}

[data-testid="stSidebar"] {
    background: linear-gradient(180deg, rgba(8, 17, 38, 0.98), rgba(4, 10, 24, 0.98));
    border-right: 1px solid rgba(73, 179, 255, 0.25);
}

.glass-panel {
    background: linear-gradient(160deg, var(--bg-panel), var(--bg-panel-soft));
    border: 1px solid var(--line);
    border-radius: 16px;
    padding: 14px 16px;
    backdrop-filter: blur(10px);
    box-shadow:
        0 0 0 1px rgba(56, 141, 255, 0.12) inset,
        0 14px 30px rgba(2, 8, 30, 0.55),
        0 0 28px rgba(63, 147, 255, 0.12);
}

.hud-header {
    border: 1px solid rgba(73, 179, 255, 0.35);
    background: linear-gradient(140deg, rgba(11, 25, 53, 0.65), rgba(8, 19, 40, 0.75));
    border-radius: 18px;
    padding: 14px 20px;
    box-shadow: 0 0 22px rgba(56, 154, 255, 0.16);
}

.hud-grid {
    background-image:
        linear-gradient(rgba(73,179,255,0.07) 1px, transparent 1px),
        linear-gradient(90deg, rgba(73,179,255,0.07) 1px, transparent 1px);
    background-size: 28px 28px;
}

.kpi-card {
    padding: 14px;
    border-radius: 14px;
    background: linear-gradient(150deg, rgba(14, 33, 66, 0.65), rgba(11, 24, 48, 0.45));
    border: 1px solid rgba(80, 167, 255, 0.28);
    box-shadow: 0 0 18px rgba(73, 179, 255, 0.16);
    min-height: 110px;
}

.kpi-title {
    color: var(--muted);
    font-size: 0.78rem;
    text-transform: uppercase;
    letter-spacing: 1px;
}

.kpi-value {
    font-size: 1.9rem;
    font-weight: 700;
    line-height: 1.15;
}

.pulse-dot {
    width: 9px;
    height: 9px;
    border-radius: 50%;
    background: #2cff94;
    box-shadow: 0 0 10px #2cff94;
    display: inline-block;
    animation: pulse 1.8s infinite;
}

@keyframes pulse {
    0% { transform: scale(0.95); opacity: 0.9; }
    70% { transform: scale(1.2); opacity: 0.4; }
    100% { transform: scale(0.95); opacity: 0.9; }
}

.ring-wrap { display: flex; align-items: center; justify-content: center; }

.ring {
    width: 188px;
    height: 188px;
    border-radius: 50%;
    display: grid;
    place-items: center;
    background:
      radial-gradient(circle closest-side, rgba(5, 14, 32, 0.95) 72%, transparent 73% 100%),
      conic-gradient(var(--orange-neon) calc(var(--p) * 1%), rgba(57, 90, 145, 0.3) 0);
    box-shadow:
      0 0 36px rgba(255, 164, 79, 0.2),
      inset 0 0 25px rgba(255, 167, 92, 0.2);
    animation: spinIn 1.2s ease;
}

@keyframes spinIn {
    from { transform: scale(0.9) rotate(-25deg); opacity: 0.2; }
    to { transform: scale(1) rotate(0deg); opacity: 1; }
}

.ring-inner { text-align: center; }
.ring-value { font-size: 2rem; font-weight: 700; color: var(--orange-neon); }
.ring-sub { color: #a8bfdc; font-size: .75rem; letter-spacing: 1px; }

.bar-row { margin-bottom: 12px; }
.bar-label {
    display: flex; justify-content: space-between; font-size: .86rem;
    color: #cfe7ff; margin-bottom: 4px;
}
.bar-track {
    height: 11px; border-radius: 999px;
    background: rgba(73, 179, 255, 0.14);
    border: 1px solid rgba(73, 179, 255, 0.3);
    overflow: hidden;
}
.bar-fill {
    height: 100%;
    border-radius: 999px;
    background: linear-gradient(90deg, #44c6ff, #ff9a3d);
    box-shadow: 0 0 18px rgba(255, 154, 61, 0.45);
}

.alert-item {
    border: 1px solid rgba(255, 92, 118, 0.45);
    background: linear-gradient(130deg, rgba(71, 14, 28, 0.78), rgba(44, 11, 22, 0.68));
    border-left: 4px solid #ff4966;
    border-radius: 12px;
    padding: 11px 12px;
    margin-bottom: 10px;
    box-shadow: 0 0 20px rgba(255, 73, 102, 0.16);
}

.alert-item.critical {
    border-color: rgba(255, 62, 95, 0.7);
    border-left-color: #ff2d55;
    background: linear-gradient(130deg, rgba(98, 12, 29, 0.86), rgba(56, 9, 18, 0.75));
    box-shadow: 0 0 24px rgba(255, 45, 85, 0.28);
}

.alert-item.high {
    border-color: rgba(255, 92, 118, 0.45);
    border-left-color: #ff4966;
}

.alert-item.medium {
    border-color: rgba(255, 161, 84, 0.4);
    border-left-color: #ff9a3d;
    background: linear-gradient(130deg, rgba(63, 34, 12, 0.7), rgba(41, 24, 9, 0.65));
}

.alert-title { font-size: .9rem; font-weight: 700; color: #ffd4dc; }
.alert-sub { color: #ffb6c2; font-size: .78rem; margin-top: 4px; }

.severity-chip {
    display: inline-block;
    font-size: 0.66rem;
    letter-spacing: 0.8px;
    text-transform: uppercase;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 999px;
    margin-bottom: 6px;
}

.severity-chip.critical { background: rgba(255, 45, 85, 0.2); color: #ff8fa3; border: 1px solid rgba(255, 45, 85, 0.45); }
.severity-chip.high { background: rgba(255, 73, 102, 0.16); color: #ffb3c0; border: 1px solid rgba(255, 73, 102, 0.4); }
.severity-chip.medium { background: rgba(255, 163, 76, 0.14); color: #ffd1a6; border: 1px solid rgba(255, 154, 61, 0.38); }

.stream-item {
    border-radius: 10px;
    border: 1px solid rgba(73, 179, 255, 0.22);
    padding: 8px 10px;
    margin-bottom: 7px;
    background: rgba(10, 21, 42, 0.5);
    font-size: 0.82rem;
}

.stream-item.success {
    border-left: 4px solid #2ce38b;
    box-shadow: inset 0 0 0 1px rgba(44, 227, 139, 0.22);
}

.stream-item.failed {
    border-left: 4px solid #ff4d68;
    box-shadow: inset 0 0 0 1px rgba(255, 77, 104, 0.2);
}

.stream-item.invalid {
    border-left: 4px solid #ffb347;
    box-shadow: inset 0 0 0 1px rgba(255, 179, 71, 0.2);
}

.section-title {
    font-size: .94rem;
    color: #a9c4e8;
    text-transform: uppercase;
    letter-spacing: 1px;
    margin-bottom: 8px;
}

.stDataFrame, [data-testid="stDataFrame"] {
    border: 1px solid rgba(73, 179, 255, 0.3);
    border-radius: 12px;
    background: rgba(9, 21, 45, 0.45);
}
</style>
"""
st.markdown(STYLES, unsafe_allow_html=True)


@st.cache_data
def load_and_analyze(
    auth_path: str,
    ssh_path: str,
    web_path: str,
    router_path: str,
    brute_force_threshold: int,
    invalid_user_threshold: int,
    start_hour: int,
    end_hour: int,
):
    parser = LogParser()
    data = parser.parse_multiple_files(
        {
            "auth": auth_path,
            "ssh": ssh_path,
            "web": web_path,
            "router": router_path,
        }
    )

    analyzer = ThreatAnalyzer(
        DetectionConfig(
            brute_force_threshold=brute_force_threshold,
            invalid_user_threshold=invalid_user_threshold,
            business_hours_start=start_hour,
            business_hours_end=end_hour,
        )
    )
    return data, analyzer.analyze(data)


def resolve_log_path(path_text: str) -> Path:
    """Resolve log path from multiple likely working directories.

    Supports running Streamlit from:
    - project root (`log_hunting_tool`)
    - repository root
    - src folder
    """
    candidate = Path(path_text)
    if candidate.is_absolute():
        return candidate

    search_roots = [
        Path.cwd(),
        APP_ROOT,
        APP_ROOT.parent,
    ]
    for root in search_roots:
        resolved = (root / candidate).resolve()
        if resolved.exists():
            return resolved

    # Return the most sensible default for downstream error display.
    return (APP_ROOT / candidate).resolve()


def is_private_or_reserved_ip(ip: str) -> bool:
    """Return True when IP is private/loopback/link-local/reserved."""
    try:
        addr = ipaddress.ip_address(str(ip))
    except ValueError:
        return False

    return bool(
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_reserved
        or addr.is_multicast
    )


def parse_watchlist_ips(raw_value: str) -> list[str]:
    """Parse analyst watchlist input into unique valid IPv4/IPv6 values."""
    if not raw_value:
        return []

    tokens = re.split(r"[,\s]+", raw_value.strip())
    cleaned: list[str] = []
    for token in tokens:
        if not token:
            continue
        try:
            cleaned.append(str(ipaddress.ip_address(token)))
        except ValueError:
            continue

    # preserve input order while deduplicating
    return list(dict.fromkeys(cleaned))


def apply_dashboard_filters(
    data: pd.DataFrame,
    event_types: list[str],
    external_only: bool,
) -> pd.DataFrame:
    """Apply analyst-selected filters for a more focused SOC view."""
    filtered = data.copy()

    if event_types:
        filtered = filtered[filtered["event_type"].isin(event_types)].copy()
    else:
        filtered = filtered.iloc[0:0].copy()

    if external_only and not filtered.empty:
        filtered = filtered[~filtered["ip_address"].astype(str).map(is_private_or_reserved_ip)].copy()

    return filtered.sort_values("timestamp").reset_index(drop=True)


def infer_geo_from_ip(ip: str) -> tuple[float, float, str]:
    """Simple deterministic geo enrichment for dashboard map visualization."""
    if ip.startswith("185.220."):
        return 52.3676, 4.9041, "Amsterdam"
    if ip.startswith("45.155."):
        return 55.7558, 37.6173, "Moscow"
    if ip.startswith("198.51."):
        return 37.7749, -122.4194, "San Francisco"
    if ip.startswith("203.0.113."):
        return 35.6762, 139.6503, "Tokyo"
    if ip.startswith("192.0.2."):
        return 52.52, 13.405, "Berlin"
    if ip.startswith("192.168."):
        return 41.8781, -87.6298, "Internal Network"
    if ip.startswith("10."):
        return 40.7128, -74.0060, "Private Segment"

    parts = [int(p) for p in ip.split(".") if p.isdigit()]
    lat = ((sum(parts[:2]) % 120) - 60) + 0.15
    lon = ((sum(parts[2:]) % 320) - 160) + 0.25
    return float(lat), float(lon), "Unknown"


def render_top_attacker_bars(top_df: pd.DataFrame) -> None:
    st.markdown('<div class="section-title">Top Attacking IPs</div>', unsafe_allow_html=True)
    if top_df.empty:
        st.info("No failed login sources found.")
        return

    max_count = max(int(top_df["failed_count"].max()), 1)
    chunks = []
    for _, row in top_df.head(6).iterrows():
        ip = str(row["ip_address"])
        count = int(row["failed_count"])
        pct = max(4, int((count / max_count) * 100))
        chunks.append(
            f"""
            <div class="bar-row">
                <div class="bar-label"><span>{ip}</span><span>{count}</span></div>
                <div class="bar-track"><div class="bar-fill" style="width: {pct}%;"></div></div>
            </div>
            """
        )

    st.markdown("\n".join(chunks), unsafe_allow_html=True)


def render_failed_ring(summary: dict[str, int]) -> None:
    failed = int(summary.get("failed_logins", 0))
    total = max(int(summary.get("total_events", 0)), 1)
    pct = min(100, int((failed / total) * 100))
    st.markdown(
        f"""
        <div class="section-title">Total Failed Login Attempts</div>
        <div class="ring-wrap">
            <div class="ring" style="--p:{pct};">
                <div class="ring-inner">
                    <div class="ring-value">{failed}</div>
                    <div class="ring-sub">FAILED ATTEMPTS</div>
                    <div class="ring-sub">{pct}% of all events</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_alerts(alerts: list[dict]) -> None:
    st.markdown('<div class="section-title">Active Alerts</div>', unsafe_allow_html=True)

    if not alerts:
        st.success("No active detections. Monitoring baseline looks stable.")
        return

    def severity_for_alert(alert: dict) -> str:
        base = str(alert.get("severity", "MEDIUM")).upper()
        alert_type = str(alert.get("alert_type", "")).upper()
        details = str(alert.get("details", ""))
        counts = [int(n) for n in re.findall(r"(\d+)", details)]
        count_hint = max(counts) if counts else 0

        if alert_type == "BRUTE_FORCE":
            if count_hint >= 6:
                return "CRITICAL"
            return "HIGH"
        if base == "HIGH":
            return "HIGH"
        return "MEDIUM"

    severity_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    ranked = sorted(alerts, key=lambda a: severity_rank.get(severity_for_alert(a), 3))

    for alert in ranked:
        sev = severity_for_alert(alert)
        css = "alert-item medium"
        if sev == "CRITICAL":
            css = "alert-item critical"
        elif sev == "HIGH":
            css = "alert-item high"

        st.markdown(
            f"""
            <div class="{css}">
                <div class="severity-chip {sev.lower()}">{sev}</div>
                <div class="alert-title">{alert.get("alert_type", "ALERT")}</div>
                <div class="alert-sub">IP: {alert.get("ip_address", "N/A")}</div>
                <div class="alert-sub">{alert.get("details", "")}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_failed_trend_chart(trend_df: pd.DataFrame) -> None:
    st.markdown('<div class="section-title">Real-time Login Attempts Trend</div>', unsafe_allow_html=True)
    if trend_df.empty:
        st.info("No failed login trend is available.")
        return

    chart_data = trend_df.copy()
    chart_data["hour"] = pd.to_datetime(chart_data["hour"])

    line = (
        alt.Chart(chart_data)
        .mark_line(interpolate="monotone", strokeWidth=3, color="#44c6ff")
        .encode(
            x=alt.X("hour:T", title="Time"),
            y=alt.Y("failed_count:Q", title="Attempts"),
            tooltip=["hour:T", "failed_count:Q"],
        )
    )
    points = (
        alt.Chart(chart_data)
        .mark_circle(size=90, color="#ff9a3d")
        .encode(x="hour:T", y="failed_count:Q")
    )

    st.altair_chart((line + points).properties(height=260), use_container_width=True)
    st.caption("Live mode: chart updates on each dashboard rerun.")


def render_login_heatmap(data: pd.DataFrame) -> None:
    st.markdown('<div class="section-title">Login Activity Heatmap (24h Timeline)</div>', unsafe_allow_html=True)

    login_events = data[data["event_type"].isin(["FAILED_LOGIN", "SUCCESS_LOGIN"])].copy()
    if login_events.empty:
        st.info("No login activity available for heatmap.")
        return

    login_events["hour"] = pd.to_datetime(login_events["timestamp"], errors="coerce").dt.hour
    login_events["status"] = login_events["event_type"].map(
        {"FAILED_LOGIN": "Failed", "SUCCESS_LOGIN": "Success"}
    )

    heat = (
        login_events.groupby(["hour", "status"]) 
        .size()
        .reset_index(name="count")
    )

    chart = (
        alt.Chart(heat)
        .mark_rect(cornerRadius=4)
        .encode(
            x=alt.X("hour:O", title="Hour of Day"),
            y=alt.Y("status:N", title=None),
            color=alt.Color(
                "count:Q",
                title="Events",
                scale=alt.Scale(range=["#132542", "#2f5e9f", "#42b7ff", "#ff9a3d", "#ff4966"]),
            ),
            tooltip=["hour:O", "status:N", "count:Q"],
        )
        .properties(height=120)
        .configure_view(strokeWidth=0)
    )

    st.altair_chart(chart, use_container_width=True)


def render_source_distribution(data: pd.DataFrame) -> None:
    st.markdown('<div class="section-title">Telemetry Source Mix</div>', unsafe_allow_html=True)
    if data.empty:
        st.info("No events available for source distribution.")
        return

    source_counts = (
        data.groupby("source")
        .size()
        .reset_index(name="events")
        .sort_values("events", ascending=False)
    )

    donut = (
        alt.Chart(source_counts)
        .mark_arc(innerRadius=46, outerRadius=88)
        .encode(
            theta=alt.Theta("events:Q"),
            color=alt.Color(
                "source:N",
                scale=alt.Scale(range=["#44c6ff", "#ff9a3d", "#b388ff", "#44ffc6"]),
                legend=alt.Legend(orient="right"),
            ),
            tooltip=["source:N", "events:Q"],
        )
        .properties(height=230)
        .configure_view(strokeWidth=0)
    )

    st.altair_chart(donut, use_container_width=True)


def render_attack_surface_matrix(data: pd.DataFrame) -> None:
    st.markdown('<div class="section-title">Attack Surface Matrix (IP × Event Type)</div>', unsafe_allow_html=True)
    if data.empty:
        st.info("No events available for matrix view.")
        return

    grouped = (
        data.groupby(["ip_address", "event_type"])
        .size()
        .reset_index(name="count")
        .sort_values("count", ascending=False)
    )
    if grouped.empty:
        st.info("Not enough events for attack matrix.")
        return

    top_ips = grouped.groupby("ip_address")["count"].sum().sort_values(ascending=False).head(10).index
    matrix_data = grouped[grouped["ip_address"].isin(top_ips)].copy()

    heat = (
        alt.Chart(matrix_data)
        .mark_rect(cornerRadius=4)
        .encode(
            x=alt.X("event_type:N", title="Event Type"),
            y=alt.Y("ip_address:N", title="IP Address", sort="-x"),
            color=alt.Color(
                "count:Q",
                title="Events",
                scale=alt.Scale(range=["#0d1b34", "#2d4f7f", "#44c6ff", "#ff9a3d", "#ff4966"]),
            ),
            tooltip=["ip_address:N", "event_type:N", "count:Q"],
        )
        .properties(height=260)
        .configure_view(strokeWidth=0)
    )
    st.altair_chart(heat, use_container_width=True)


def render_watchlist_hits(data: pd.DataFrame, watchlist_ips: list[str]) -> None:
    st.markdown('<div class="section-title">IOC Watchlist Monitor</div>', unsafe_allow_html=True)

    if not watchlist_ips:
        st.info("Add comma-separated IPs in the sidebar to activate watchlist monitoring.")
        return

    watchlist_set = set(watchlist_ips)
    hits = data[data["ip_address"].astype(str).isin(watchlist_set)].copy()

    st.markdown(
        f"<div style='color:#8ca6c9;font-size:0.82rem;margin-bottom:6px;'>Watching {len(watchlist_set)} IOC IP(s)</div>",
        unsafe_allow_html=True,
    )

    if hits.empty:
        st.success("No current matches for configured watchlist IOCs.")
        return

    hits = hits.sort_values("timestamp", ascending=False)
    total_hits = int(len(hits))
    unique_iocs = int(hits["ip_address"].nunique())

    c1, c2 = st.columns(2)
    with c1:
        st.metric("Watchlist Hits", total_hits)
    with c2:
        st.metric("IOC IPs Triggered", unique_iocs)

    table = hits[["timestamp", "ip_address", "event_type", "source", "raw_log"]].copy().head(30)
    table["timestamp"] = pd.to_datetime(table["timestamp"], errors="coerce").dt.strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    table = table.rename(columns={"raw_log": "details"})

    st.dataframe(table, hide_index=True, use_container_width=True)

    st.download_button(
        label="⬇️ Export Watchlist Hits (CSV)",
        data=table.to_csv(index=False),
        file_name="watchlist_hits.csv",
        mime="text/csv",
        use_container_width=True,
    )


def render_log_stream(data: pd.DataFrame) -> None:
    st.markdown('<div class="section-title">Real-time Log Stream</div>', unsafe_allow_html=True)
    if data.empty:
        st.info("No events available for stream.")
        return

    stream_df = data.sort_values("timestamp", ascending=False).head(14).copy()
    for _, row in stream_df.iterrows():
        event_type = str(row.get("event_type", "WEB_EVENT"))
        ts = pd.to_datetime(row.get("timestamp"), errors="coerce")
        timestamp = ts.strftime("%H:%M:%S") if pd.notna(ts) else "--:--:--"
        ip = str(row.get("ip_address", "N/A"))

        css = "stream-item"
        label_color = "#cde3ff"
        if event_type == "SUCCESS_LOGIN":
            css += " success"
            label_color = "#7ef7b8"
        elif event_type == "FAILED_LOGIN":
            css += " failed"
            label_color = "#ff8ca0"
        elif event_type == "INVALID_USER":
            css += " invalid"
            label_color = "#ffd49a"

        st.markdown(
            f"""
            <div class="{css}">
                <div style="display:flex;justify-content:space-between;gap:10px;">
                    <span style="color:#9bb5d9;">{timestamp}</span>
                    <span style="font-family:monospace;color:#9fd2ff;">{ip}</span>
                </div>
                <div style="color:{label_color};font-weight:700;margin-top:4px;">{event_type}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_attack_map(failed_df: pd.DataFrame) -> None:
    st.markdown('<div class="section-title">Attack Origin Map (Interactive)</div>', unsafe_allow_html=True)
    if failed_df.empty:
        st.info("No failed events available for origin mapping.")
        return

    grouped = (
        failed_df.groupby("ip_address")
        .size()
        .reset_index(name="attempts")
        .sort_values("attempts", ascending=False)
        .head(25)
        .reset_index(drop=True)
    )

    points = []
    hq_lat, hq_lon = 41.8781, -87.6298
    for _, row in grouped.iterrows():
        ip = str(row["ip_address"])
        attempts = int(row["attempts"])
        lat, lon, city = infer_geo_from_ip(ip)
        points.append(
            {
                "ip_address": ip,
                "attempts": attempts,
                "city": city,
                "source_lat": lat,
                "source_lon": lon,
                "target_lat": hq_lat,
                "target_lon": hq_lon,
            }
        )

    map_df = pd.DataFrame(points)
    if map_df.empty:
        st.info("No map points to display.")
        return

    arc_layer = pdk.Layer(
        "ArcLayer",
        data=map_df,
        get_source_position="[source_lon, source_lat]",
        get_target_position="[target_lon, target_lat]",
        get_source_color="[68, 198, 255, 180]",
        get_target_color="[255, 154, 61, 220]",
        get_width="max(1, attempts)",
        pickable=True,
        auto_highlight=True,
    )

    src_layer = pdk.Layer(
        "ScatterplotLayer",
        data=map_df,
        get_position="[source_lon, source_lat]",
        get_color="[255, 154, 61, 220]",
        get_radius="max(40000, attempts * 25000)",
        pickable=True,
    )

    hq_layer = pdk.Layer(
        "ScatterplotLayer",
        data=pd.DataFrame(
            [{"label": "SOC HQ", "lon": hq_lon, "lat": hq_lat, "radius": 95000}]
        ),
        get_position="[lon, lat]",
        get_color="[68, 198, 255, 240]",
        get_radius="radius",
        pickable=True,
    )

    tooltip = {
        "html": "<b>IP:</b> {ip_address}<br/><b>Attempts:</b> {attempts}<br/><b>Origin:</b> {city}",
        "style": {
            "backgroundColor": "rgba(10, 20, 45, 0.95)",
            "color": "#d9eeff",
            "border": "1px solid #49b3ff",
        },
    }

    deck = pdk.Deck(
        layers=[arc_layer, src_layer, hq_layer],
        initial_view_state=pdk.ViewState(latitude=20, longitude=0, zoom=1.15, pitch=20),
        map_style="mapbox://styles/mapbox/dark-v10",
        tooltip=tooltip,
    )
    st.pydeck_chart(deck, use_container_width=True)


def build_recent_activity(data: pd.DataFrame) -> pd.DataFrame:
    recent = data.sort_values("timestamp", ascending=False).head(18).copy()
    recent["timestamp"] = pd.to_datetime(recent["timestamp"], errors="coerce").dt.strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    recent["details"] = recent["raw_log"].astype(str).str.slice(0, 100)
    return recent[["timestamp", "ip_address", "event_type", "details"]]


def render_header() -> None:
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.markdown(
        f"""
        <div class="hud-header hud-grid">
            <div style="display:flex;justify-content:space-between;align-items:center;gap:16px;">
                <div>
                    <div style="font-size:1.7rem;font-weight:700;color:#d9eeff;">🛡️ NEON SIEM Command Center</div>
                    <div style="color:#8ca6c9;font-size:0.9rem;">Enterprise SOC Dashboard · Threat Hunting & Log Intelligence</div>
                </div>
                <div style="text-align:right;">
                    <div style="color:#8ca6c9;font-size:0.78rem;">SYSTEM STATUS</div>
                    <div style="display:flex;align-items:center;gap:8px;justify-content:flex-end;color:#d9eeff;font-weight:600;">
                        <span class="pulse-dot"></span>
                        LIVE MONITORING · {now}
                    </div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_kpis(summary: dict, alert_count: int) -> None:
    c1, c2, c3, c4 = st.columns(4)
    cards = [
        ("Total Events", int(summary.get("total_events", 0)), "#49b3ff"),
        ("Failed Logins", int(summary.get("failed_logins", 0)), "#ff9a3d"),
        ("Successful Logins", int(summary.get("success_logins", 0)), "#51ffa6"),
        ("Active Alerts", alert_count, "#ff4966" if alert_count else "#51ffa6"),
    ]

    for container, (title, value, color) in zip([c1, c2, c3, c4], cards):
        with container:
            st.markdown(
                f"""
                <div class="kpi-card">
                    <div class="kpi-title">{title}</div>
                    <div class="kpi-value" style="color:{color};">{value}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )


def render_ai_insights(data: pd.DataFrame, results: dict) -> None:
    """Render AI-powered insights panel with anomaly scores and risk levels."""
    st.markdown('<div class="section-title">🧠 AI Security Insights</div>', unsafe_allow_html=True)
    
    # Calculate AI-style metrics
    total_events = len(data)
    failed_count = int(results["summary"].get("failed_logins", 0))
    alert_count = len(results["alerts"])
    
    # Anomaly Score (0-100)
    anomaly_ratio = failed_count / max(total_events, 1)
    anomaly_score = min(100, int((anomaly_ratio * 200) + (alert_count * 15)))
    
    # Risk Level
    if anomaly_score >= 70:
        risk_level = "CRITICAL"
        risk_color = "#ff4966"
        risk_icon = "🔴"
    elif anomaly_score >= 40:
        risk_level = "HIGH"
        risk_color = "#ff9a3d"
        risk_icon = "🟠"
    elif anomaly_score >= 20:
        risk_level = "MEDIUM"
        risk_color = "#f5d033"
        risk_icon = "🟡"
    else:
        risk_level = "LOW"
        risk_color = "#51ffa6"
        risk_icon = "🟢"
    
    # Top threats (top 5)
    top_threat_rows = []
    if not results["top_attacking_ips"].empty:
        top_threat_rows = results["top_attacking_ips"].head(5).to_dict("records")

    top_threat_html = "<div style='color:#8ca6c9;font-size:0.78rem;'>No threat data</div>"
    if top_threat_rows:
        top_threat_html = "".join(
            [
                (
                    "<div style='display:flex;justify-content:space-between;gap:10px;"
                    "margin:4px 0;color:#d9eeff;font-size:0.78rem;'>"
                    f"<span style='font-family:monospace;color:#ff9a3d;'>{str(row.get('ip_address', 'N/A'))}</span>"
                    f"<span style='color:#8ca6c9;'>{int(row.get('failed_count', 0))} attempts</span>"
                    "</div>"
                )
                for row in top_threat_rows
            ]
        )
    
    st.markdown(
        f"""
        <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin-top: 8px;">
            <div style="background: linear-gradient(145deg, rgba(14,33,66,0.65), rgba(11,24,48,0.45)); border: 1px solid rgba(80,167,255,0.28); border-radius: 12px; padding: 16px; text-align: center;">
                <div style="color: #8ca6c9; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">Anomaly Score</div>
                <div style="font-size: 2.2rem; font-weight: 700; color: {risk_color};">{anomaly_score}%</div>
            </div>
            <div style="background: linear-gradient(145deg, rgba(14,33,66,0.65), rgba(11,24,48,0.45)); border: 1px solid rgba(80,167,255,0.28); border-radius: 12px; padding: 16px; text-align: center;">
                <div style="color: #8ca6c9; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">Risk Level</div>
                <div style="font-size: 1.4rem; font-weight: 700; color: {risk_color};">{risk_icon} {risk_level}</div>
            </div>
            <div style="background: linear-gradient(145deg, rgba(14,33,66,0.65), rgba(11,24,48,0.45)); border: 1px solid rgba(80,167,255,0.28); border-radius: 12px; padding: 16px; text-align: left;">
                <div style="color: #8ca6c9; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">Top Threat</div>
                {top_threat_html}
            </div>
            <div style="background: linear-gradient(145deg, rgba(14,33,66,0.65), rgba(11,24,48,0.45)); border: 1px solid rgba(80,167,255,0.28); border-radius: 12px; padding: 16px; text-align: center;">
                <div style="color: #8ca6c9; font-size: 0.75rem; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">Threats Detected</div>
                <div style="font-size: 2.2rem; font-weight: 700; color: {'#ff4966' if alert_count > 0 else '#51ffa6'};">{alert_count}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    
    # AI Recommendations
    st.markdown('<div style="margin-top: 16px; color: #8ca6c9; font-size: 0.85rem;">🤖 AI Recommendations:</div>', unsafe_allow_html=True)
    
    recommendations = []
    if anomaly_score >= 40:
        recommendations.append("⚠️ Immediate action recommended - block top attacking IPs")
    if top_threat_rows:
        top_ip = str(top_threat_rows[0].get("ip_address", "N/A"))
        top_ip_count = int(top_threat_rows[0].get("failed_count", 0))
        if top_ip_count >= 5:
            recommendations.append(f"🔒 Consider rate-limiting for IP {top_ip}")
    if results["invalid_user_attempts"].shape[0] > 0:
        recommendations.append("👤 Review invalid user attempts for account enumeration")
    if results["suspicious_logins"].shape[0] > 0:
        recommendations.append("🌙 Investigate off-hours login patterns")
    if not recommendations:
        recommendations.append("✅ System appears healthy - continue monitoring")
    
    for rec in recommendations:
        st.markdown(f'<div style="color: #d9eeff; font-size: 0.85rem; margin: 4px 0;">{rec}</div>', unsafe_allow_html=True)


def main() -> None:
    render_header()

    with st.sidebar:
        st.markdown("### ⚙️ Detection Controls")
        brute_force_threshold = st.slider("Brute Force Threshold", 2, 20, 5)
        invalid_user_threshold = st.slider("Invalid User Threshold", 2, 20, 3)
        start_hour, end_hour = st.select_slider("Business Hours", options=list(range(24)), value=(8, 20))
        st.markdown("---")
        st.markdown("### 📁 Log Sources")
        auth_path = st.text_input("auth.log", DEFAULT_LOG_FILES["auth"])
        ssh_path = st.text_input("ssh.log", DEFAULT_LOG_FILES["ssh"])
        web_path = st.text_input("web.log", DEFAULT_LOG_FILES["web"])
        router_path = st.text_input("router.log", DEFAULT_LOG_FILES["router"])
        st.markdown("---")
        st.markdown("### 🎛️ Analyst Filters")
        event_filter = st.multiselect(
            "Event Types",
            options=["FAILED_LOGIN", "SUCCESS_LOGIN", "INVALID_USER", "WEB_EVENT"],
            default=["FAILED_LOGIN", "SUCCESS_LOGIN", "INVALID_USER", "WEB_EVENT"],
        )
        external_only = st.checkbox("External IPs only", value=False)
        watchlist_input = st.text_area(
            "IOC Watchlist (comma or newline separated IPs)",
            value="185.220.101.10, 198.51.100.99",
            height=80,
        )

    resolved_paths = {
        "auth": resolve_log_path(auth_path),
        "ssh": resolve_log_path(ssh_path),
        "web": resolve_log_path(web_path),
        "router": resolve_log_path(router_path),
    }

    for source, resolved in resolved_paths.items():
        if not resolved.exists():
            st.error(
                f"File not found for {source}.log: {resolved}. "
                "Use an absolute path or a path relative to project root."
            )
            st.stop()

    data, _ = load_and_analyze(
        auth_path=str(resolved_paths["auth"]),
        ssh_path=str(resolved_paths["ssh"]),
        web_path=str(resolved_paths["web"]),
        router_path=str(resolved_paths["router"]),
        brute_force_threshold=brute_force_threshold,
        invalid_user_threshold=invalid_user_threshold,
        start_hour=start_hour,
        end_hour=end_hour,
    )

    display_data = apply_dashboard_filters(
        data=data,
        event_types=event_filter,
        external_only=external_only,
    )
    watchlist_ips = parse_watchlist_ips(watchlist_input)

    analyzer = ThreatAnalyzer(
        DetectionConfig(
            brute_force_threshold=brute_force_threshold,
            invalid_user_threshold=invalid_user_threshold,
            business_hours_start=start_hour,
            business_hours_end=end_hour,
        )
    )
    results = analyzer.analyze(display_data)

    if display_data.empty:
        st.warning("No events match the current analyst filters. Adjust sidebar filters to continue triage.")

    render_kpis(results["summary"], len(results["alerts"]))
    st.markdown("<div style='height:10px;'></div>", unsafe_allow_html=True)
    
    # AI Insights Panel
    st.markdown("<div class='glass-panel'>", unsafe_allow_html=True)
    render_ai_insights(data, results)
    st.markdown("</div>", unsafe_allow_html=True)
    st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)
    
    left, mid, right = st.columns([1.15, 1.0, 1.25])

    with left:
        st.markdown("<div class='glass-panel'>", unsafe_allow_html=True)
        render_top_attacker_bars(results["top_attacking_ips"])
        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)
        st.markdown("<div class='glass-panel'>", unsafe_allow_html=True)
        render_alerts(results["alerts"])
        st.markdown("</div>", unsafe_allow_html=True)

    with mid:
        st.markdown("<div class='glass-panel'>", unsafe_allow_html=True)
        render_failed_ring(results["summary"])
        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)
        st.markdown("<div class='glass-panel'>", unsafe_allow_html=True)
        render_failed_trend_chart(results["failed_login_trend"])
        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)
        st.markdown("<div class='glass-panel'>", unsafe_allow_html=True)
        render_login_heatmap(display_data)
        st.markdown("</div>", unsafe_allow_html=True)

    with right:
        st.markdown("<div class='glass-panel'>", unsafe_allow_html=True)
        failed_events = display_data[display_data["event_type"] == "FAILED_LOGIN"].copy()
        render_attack_map(failed_events)
        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)
        st.markdown("<div class='glass-panel'>", unsafe_allow_html=True)
        render_log_stream(display_data)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)
    x1, x2 = st.columns([1.05, 1.2])

    with x1:
        st.markdown("<div class='glass-panel'>", unsafe_allow_html=True)
        render_source_distribution(display_data)
        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)
        st.markdown("<div class='glass-panel'>", unsafe_allow_html=True)
        render_attack_surface_matrix(display_data)
        st.markdown("</div>", unsafe_allow_html=True)

    with x2:
        st.markdown("<div class='glass-panel'>", unsafe_allow_html=True)
        render_watchlist_hits(display_data, watchlist_ips)
        st.markdown("</div>", unsafe_allow_html=True)

    st.markdown("<div style='height:12px;'></div>", unsafe_allow_html=True)
    st.markdown("<div class='glass-panel'>", unsafe_allow_html=True)
    st.markdown('<div class="section-title">Recent Log Activity</div>', unsafe_allow_html=True)
    recent = build_recent_activity(display_data)
    st.dataframe(
        recent,
        use_container_width=True,
        hide_index=True,
        column_config={
            "timestamp": st.column_config.TextColumn("timestamp"),
            "ip_address": st.column_config.TextColumn("IP"),
            "event_type": st.column_config.TextColumn("event type"),
            "details": st.column_config.TextColumn("details", width="large"),
        },
    )
    st.download_button(
        "⬇️ Export Recent Activity (CSV)",
        data=recent.to_csv(index=False),
        file_name="recent_log_activity.csv",
        mime="text/csv",
        use_container_width=True,
    )
    st.markdown("</div>", unsafe_allow_html=True)


if __name__ == "__main__":
    main()
