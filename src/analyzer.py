"""
analyzer.py
-----------
Threat hunting logic for parsed log events.

This module takes a normalized DataFrame from parser.py and performs
simple but practical SOC analytics:
1) brute-force detection
2) suspicious login time detection
3) repeated invalid user detection
4) alert generation when thresholds are exceeded
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

import pandas as pd


@dataclass
class DetectionConfig:
    """Tunable thresholds for detections."""

    brute_force_threshold: int = 5
    invalid_user_threshold: int = 3
    business_hours_start: int = 8   # 08:00
    business_hours_end: int = 20    # 20:00 (exclusive)


class ThreatAnalyzer:
    """Run anomaly detection and create analyst-friendly outputs."""

    def __init__(self, config: DetectionConfig | None = None) -> None:
        self.config = config or DetectionConfig()

    def analyze(self, df: pd.DataFrame) -> Dict[str, pd.DataFrame | List[Dict] | Dict]:
        """
        Run all detections and return a bundle of results.
        """
        if df.empty:
            empty_df = pd.DataFrame()
            return {
                "top_attacking_ips": empty_df,
                "failed_login_trend": empty_df,
                "brute_force": empty_df,
                "suspicious_logins": empty_df,
                "invalid_user_attempts": empty_df,
                "alerts": [],
                "summary": {
                    "total_events": 0,
                    "failed_logins": 0,
                    "success_logins": 0,
                },
            }

        data = df.copy()
        data["timestamp"] = pd.to_datetime(data["timestamp"], errors="coerce")

        top_attacking_ips = self.get_top_attacking_ips(data)
        failed_login_trend = self.get_failed_login_trend(data)
        brute_force = self.detect_brute_force(data)
        suspicious_logins = self.detect_suspicious_login_times(data)
        invalid_user_attempts = self.detect_repeated_invalid_users(data)
        alerts = self.generate_alerts(brute_force, suspicious_logins, invalid_user_attempts)

        summary = {
            "total_events": int(len(data)),
            "failed_logins": int((data["event_type"] == "FAILED_LOGIN").sum()),
            "success_logins": int((data["event_type"] == "SUCCESS_LOGIN").sum()),
        }

        return {
            "top_attacking_ips": top_attacking_ips,
            "failed_login_trend": failed_login_trend,
            "brute_force": brute_force,
            "suspicious_logins": suspicious_logins,
            "invalid_user_attempts": invalid_user_attempts,
            "alerts": alerts,
            "summary": summary,
        }

    def get_top_attacking_ips(self, df: pd.DataFrame, top_n: int = 10) -> pd.DataFrame:
        """Return IPs with the highest FAILED_LOGIN counts."""
        failed = df[df["event_type"] == "FAILED_LOGIN"]
        if failed.empty:
            return pd.DataFrame(columns=["ip_address", "failed_count"])

        agg = (
            failed.groupby("ip_address")
            .size()
            .reset_index(name="failed_count")
            .sort_values("failed_count", ascending=False)
            .head(top_n)
            .reset_index(drop=True)
        )
        return agg

    def get_failed_login_trend(self, df: pd.DataFrame) -> pd.DataFrame:
        """Hourly trend of failed logins."""
        failed = df[df["event_type"] == "FAILED_LOGIN"].copy()
        if failed.empty:
            return pd.DataFrame(columns=["hour", "failed_count"])

        failed["hour"] = failed["timestamp"].dt.floor("h")
        trend = (
            failed.groupby("hour")
            .size()
            .reset_index(name="failed_count")
            .sort_values("hour")
        )
        return trend

    def detect_brute_force(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Flag IPs with too many failed logins.
        """
        failed = df[df["event_type"] == "FAILED_LOGIN"]
        if failed.empty:
            return pd.DataFrame(columns=["ip_address", "failed_count"])

        grouped = (
            failed.groupby("ip_address")
            .size()
            .reset_index(name="failed_count")
            .sort_values("failed_count", ascending=False)
        )

        return grouped[grouped["failed_count"] >= self.config.brute_force_threshold].reset_index(
            drop=True
        )

    def detect_suspicious_login_times(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Identify successful logins outside business hours.
        """
        success = df[df["event_type"] == "SUCCESS_LOGIN"].copy()
        if success.empty:
            return pd.DataFrame(columns=df.columns)

        success["hour"] = success["timestamp"].dt.hour
        suspicious = success[
            (success["hour"] < self.config.business_hours_start)
            | (success["hour"] >= self.config.business_hours_end)
        ].copy()

        return suspicious.drop(columns=["hour"]).reset_index(drop=True)

    def detect_repeated_invalid_users(self, df: pd.DataFrame) -> pd.DataFrame:
        """
        Detect repeated invalid user attempts from the same IP.
        """
        invalid = df[df["event_type"] == "INVALID_USER"]
        if invalid.empty:
            return pd.DataFrame(columns=["ip_address", "username", "attempt_count"])

        grouped = (
            invalid.groupby(["ip_address", "username"])
            .size()
            .reset_index(name="attempt_count")
            .sort_values("attempt_count", ascending=False)
        )

        return grouped[
            grouped["attempt_count"] >= self.config.invalid_user_threshold
        ].reset_index(drop=True)

    def generate_alerts(
        self,
        brute_force_df: pd.DataFrame,
        suspicious_logins_df: pd.DataFrame,
        invalid_users_df: pd.DataFrame,
    ) -> List[Dict]:
        """Build alert objects for SOC triage."""
        alerts: List[Dict] = []

        for _, row in brute_force_df.iterrows():
            alerts.append(
                {
                    "severity": "HIGH",
                    "alert_type": "BRUTE_FORCE",
                    "ip_address": row["ip_address"],
                    "details": f"{int(row['failed_count'])} failed login attempts detected.",
                }
            )

        for _, row in suspicious_logins_df.iterrows():
            alerts.append(
                {
                    "severity": "MEDIUM",
                    "alert_type": "SUSPICIOUS_LOGIN_TIME",
                    "ip_address": row.get("ip_address"),
                    "details": (
                        f"Successful login by user '{row.get('username')}' at "
                        f"{row.get('timestamp')} outside business hours."
                    ),
                }
            )

        for _, row in invalid_users_df.iterrows():
            alerts.append(
                {
                    "severity": "MEDIUM",
                    "alert_type": "REPEATED_INVALID_USER",
                    "ip_address": row["ip_address"],
                    "details": (
                        f"Invalid user '{row['username']}' attempted "
                        f"{int(row['attempt_count'])} times."
                    ),
                }
            )

        return alerts
