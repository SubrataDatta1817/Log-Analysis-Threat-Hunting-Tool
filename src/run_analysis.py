"""
run_analysis.py
---------------
CLI runner for quick SOC analysis from terminal.

Usage:
    python src/run_analysis.py
"""

from __future__ import annotations

from analyzer import ThreatAnalyzer
from parser import LogParser


def main() -> None:
    parser = LogParser()
    df = parser.parse_multiple_files(
        {
            "auth": "sample_logs/auth.log",
            "ssh": "sample_logs/ssh.log",
            "web": "sample_logs/web.log",
        }
    )

    analyzer = ThreatAnalyzer()
    results = analyzer.analyze(df)

    print("=== SOC SUMMARY ===")
    print(results["summary"])
    print("\n=== TOP ATTACKING IPS ===")
    print(results["top_attacking_ips"])
    print("\n=== ALERTS ===")
    for alert in results["alerts"]:
        print(alert)


if __name__ == "__main__":
    main()
