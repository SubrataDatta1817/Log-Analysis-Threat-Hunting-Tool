"""
parser.py
---------
SOC-focused log parsing module.

This module reads Linux auth/SSH logs and web access logs, then extracts
security-relevant fields with regex and returns a normalized Pandas DataFrame.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List

import pandas as pd


class LogParser:
    """Parse different log sources into a single normalized schema."""

    # Example: "Apr  9 01:15:22"
    AUTH_PREFIX_REGEX = re.compile(
        r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s\d{2}:\d{2}:\d{2})\s"
        r"(?P<host>\S+)\s(?P<process>[^:]+):\s(?P<message>.*)$"
    )

    FAILED_LOGIN_REGEX = re.compile(
        r"Failed password for (invalid user )?(?P<username>\S+) from "
        r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    )
    SUCCESS_LOGIN_REGEX = re.compile(
        r"Accepted password for (?P<username>\S+) from "
        r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    )
    INVALID_USER_REGEX = re.compile(
        r"Invalid user (?P<username>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    )

    # Apache/Nginx style access log (common format + request/status extraction)
    WEB_LOG_REGEX = re.compile(
        r"^(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s\S+\s\S+\s"
        r"\[(?P<timestamp>[^\]]+)\]\s"
        r'"(?P<method>[A-Z]+)\s(?P<path>[^\s]+)\sHTTP/[0-9.]+"\s'
        r"(?P<status>\d{3})\s(?P<size>\S+)"
    )

    # Router/firewall-style logs, e.g.:
    # Apr  9 00:45:10 edge-router kernel: DROP IN=eth0 OUT= MAC=... SRC=198.51.100.200 DST=10.0.0.10
    ROUTER_ACTION_REGEX = re.compile(r"\b(?P<action>DROP|REJECT|BLOCK|ALLOW|ACCEPT)\b")
    ROUTER_SRC_REGEX = re.compile(r"\bSRC=(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\b")

    def parse_file(self, file_path: str, log_type: str) -> pd.DataFrame:
        """
        Parse a single file and return structured events.

        Args:
            file_path: path to log file
            log_type: one of {"auth", "ssh", "web", "router"}
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {file_path}")

        rows: List[Dict] = []
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                if log_type in {"auth", "ssh"}:
                    event = self._parse_auth_or_ssh_line(line, log_type)
                elif log_type == "web":
                    event = self._parse_web_line(line)
                elif log_type == "router":
                    event = self._parse_router_line(line)
                else:
                    raise ValueError("Unsupported log_type. Use auth, ssh, web, or router.")

                if event:
                    rows.append(event)

        columns = [
            "source",
            "timestamp",
            "ip_address",
            "event_type",
            "username",
            "status_code",
            "raw_log",
        ]
        if not rows:
            return pd.DataFrame(columns=columns)

        df = pd.DataFrame(rows)
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
        return df[columns]

    def parse_multiple_files(self, file_map: Dict[str, str]) -> pd.DataFrame:
        """
        Parse multiple files and return one combined DataFrame.

        Example file_map:
            {
                "auth": "sample_logs/auth.log",
                "ssh": "sample_logs/ssh.log",
                "web": "sample_logs/web.log",
                "router": "sample_logs/router.log",
            }
        """
        frames = []
        for log_type, file_path in file_map.items():
            frame = self.parse_file(file_path=file_path, log_type=log_type)
            frames.append(frame)

        if not frames:
            return pd.DataFrame()

        combined = pd.concat(frames, ignore_index=True)
        return combined.sort_values("timestamp").reset_index(drop=True)

    def _parse_auth_or_ssh_line(self, line: str, source: str) -> Dict | None:
        prefix_match = self.AUTH_PREFIX_REGEX.search(line)
        if not prefix_match:
            return None

        timestamp_text = prefix_match.group("timestamp")
        message = prefix_match.group("message")
        timestamp = self._parse_syslog_timestamp(timestamp_text)

        # Failed login can include "invalid user" text inside failed-password message.
        failed_match = self.FAILED_LOGIN_REGEX.search(message)
        if failed_match:
            username = failed_match.group("username")
            if "invalid user" in message:
                event_type = "INVALID_USER"
            else:
                event_type = "FAILED_LOGIN"

            return {
                "source": source,
                "timestamp": timestamp,
                "ip_address": failed_match.group("ip"),
                "event_type": event_type,
                "username": username,
                "status_code": None,
                "raw_log": line,
            }

        success_match = self.SUCCESS_LOGIN_REGEX.search(message)
        if success_match:
            return {
                "source": source,
                "timestamp": timestamp,
                "ip_address": success_match.group("ip"),
                "event_type": "SUCCESS_LOGIN",
                "username": success_match.group("username"),
                "status_code": None,
                "raw_log": line,
            }

        invalid_match = self.INVALID_USER_REGEX.search(message)
        if invalid_match:
            return {
                "source": source,
                "timestamp": timestamp,
                "ip_address": invalid_match.group("ip"),
                "event_type": "INVALID_USER",
                "username": invalid_match.group("username"),
                "status_code": None,
                "raw_log": line,
            }

        return None

    def _parse_web_line(self, line: str) -> Dict | None:
        match = self.WEB_LOG_REGEX.search(line)
        if not match:
            return None

        ip = match.group("ip")
        status_code = int(match.group("status"))
        path = match.group("path")
        timestamp = self._parse_web_timestamp(match.group("timestamp"))

        # SOC heuristic: classify login endpoint attempts by status code.
        event_type = "WEB_EVENT"
        if "login" in path.lower():
            if 200 <= status_code < 400:
                event_type = "SUCCESS_LOGIN"
            else:
                event_type = "FAILED_LOGIN"

        return {
            "source": "web",
            "timestamp": timestamp,
            "ip_address": ip,
            "event_type": event_type,
            "username": None,
            "status_code": status_code,
            "raw_log": line,
        }

    def _parse_router_line(self, line: str) -> Dict | None:
        """Parse router/firewall logs into normalized events."""
        prefix_match = self.AUTH_PREFIX_REGEX.search(line)
        if not prefix_match:
            return None

        timestamp_text = prefix_match.group("timestamp")
        message = prefix_match.group("message")
        timestamp = self._parse_syslog_timestamp(timestamp_text)

        src_match = self.ROUTER_SRC_REGEX.search(message)
        action_match = self.ROUTER_ACTION_REGEX.search(message)
        if not src_match:
            return None

        action = (action_match.group("action") if action_match else "UNKNOWN").upper()
        # Reuse existing event-type taxonomy for dashboard compatibility.
        event_type = "FAILED_LOGIN" if action in {"DROP", "REJECT", "BLOCK"} else "SUCCESS_LOGIN"

        return {
            "source": "router",
            "timestamp": timestamp,
            "ip_address": src_match.group("ip"),
            "event_type": event_type,
            "username": None,
            "status_code": None,
            "raw_log": line,
        }

    @staticmethod
    def _parse_syslog_timestamp(timestamp_text: str) -> datetime:
        """Convert syslog timestamp (without year) into datetime with current year."""
        current_year = datetime.now().year
        return datetime.strptime(f"{current_year} {timestamp_text}", "%Y %b %d %H:%M:%S")

    @staticmethod
    def _parse_web_timestamp(timestamp_text: str) -> datetime | None:
        """Parse web log timestamp: 09/Apr/2026:01:10:00 +0000"""
        try:
            return datetime.strptime(timestamp_text, "%d/%b/%Y:%H:%M:%S %z").replace(
                tzinfo=None
            )
        except ValueError:
            return None


if __name__ == "__main__":
    # Quick local smoke test usage.
    parser = LogParser()
    data = parser.parse_multiple_files(
        {
            "auth": "sample_logs/auth.log",
            "ssh": "sample_logs/ssh.log",
            "web": "sample_logs/web.log",
            "router": "sample_logs/router.log",
        }
    )
    print(data.head())
