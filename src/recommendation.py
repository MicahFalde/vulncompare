"""Recommendation logic and summary generation for VulnCompare."""

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from .models import ComparisonResult, ScanResult, Vulnerability


@dataclass
class Recommendation:
    """Structured recommendation output."""
    winner: str  # "chainguard", "dhi", or "none"
    headline: str
    bullets: List[str]
    confidence: str  # "high", "medium", "low"


def get_recommendation(result: ComparisonResult) -> Recommendation:
    """
    Generate a recommendation based on vulnerability comparison.

    Rules:
    1. Fewer Critical vulnerabilities wins
    2. If tied on Critical, fewer High wins
    3. If tied on High, fewer total vulnerabilities wins
    4. If tied on all, no clear winner
    """
    if not result.cg_result or not result.dhi_result:
        return Recommendation(
            winner="none",
            headline="Comparison incomplete",
            bullets=["Unable to compare: missing scan results"],
            confidence="low"
        )

    if result.cg_result.has_error or result.dhi_result.has_error:
        return Recommendation(
            winner="none",
            headline="Comparison incomplete",
            bullets=["One or both scans encountered errors"],
            confidence="low"
        )

    cg = result.cg_result
    dhi = result.dhi_result

    bullets = []
    winner = "none"
    confidence = "low"

    # Compare Critical
    crit_diff = dhi.critical - cg.critical
    if crit_diff != 0:
        bullets.append(f"Critical: {cg.critical} vs {dhi.critical}")
        if crit_diff > 0:
            winner = "chainguard"
            confidence = "high"
        else:
            winner = "dhi"
            confidence = "high"
    else:
        bullets.append(f"Critical: {cg.critical} vs {dhi.critical} (tied)")

    # Compare High
    high_diff = dhi.high - cg.high
    if high_diff != 0:
        bullets.append(f"High: {cg.high} vs {dhi.high}")
        if winner == "none":
            if high_diff > 0:
                winner = "chainguard"
                confidence = "high"
            else:
                winner = "dhi"
                confidence = "high"
    else:
        bullets.append(f"High: {cg.high} vs {dhi.high} (tied)")

    # Compare Total
    total_diff = dhi.total_vulns - cg.total_vulns
    bullets.append(f"Total: {cg.total_vulns} vs {dhi.total_vulns}")

    if winner == "none" and total_diff != 0:
        if total_diff > 0:
            winner = "chainguard"
            confidence = "medium"
        else:
            winner = "dhi"
            confidence = "medium"

    # Generate headline
    if winner == "chainguard":
        headline = "Recommended: Chainguard"
    elif winner == "dhi":
        headline = "Recommended: Docker Hardened Images"
    else:
        headline = "No clear winner"
        confidence = "low"

    return Recommendation(
        winner=winner,
        headline=headline,
        bullets=bullets,
        confidence=confidence
    )


def generate_summary_text(result: ComparisonResult, recommendation: Recommendation) -> str:
    """Generate a clipboard-ready summary text."""
    lines = [
        f"VulnCompare Summary: {result.image_name}",
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
        "",
        recommendation.headline,
        "",
    ]

    for bullet in recommendation.bullets:
        lines.append(f"  - {bullet}")

    lines.append("")

    summary = result.get_summary()
    lines.append("Severity Breakdown:")
    lines.append(f"  Chainguard: {summary['CRITICAL']['cg']}C / {summary['HIGH']['cg']}H / {summary['MEDIUM']['cg']}M / {summary['LOW']['cg']}L")
    lines.append(f"  Docker Hardened: {summary['CRITICAL']['dhi']}C / {summary['HIGH']['dhi']}H / {summary['MEDIUM']['dhi']}M / {summary['LOW']['dhi']}L")

    lines.append("")
    lines.append(f"Unique CVEs in Chainguard: {len(result.cg_unique_cves)}")
    lines.append(f"Unique CVEs in Docker Hardened: {len(result.dhi_unique_cves)}")
    lines.append(f"Common CVEs: {len(result.common_cves)}")

    return "\n".join(lines)


def export_comparison_json(result: ComparisonResult) -> str:
    """Export comparison result to JSON string."""
    def scan_to_dict(scan: Optional[ScanResult]) -> Optional[Dict]:
        if scan is None:
            return None
        return {
            "image": scan.image,
            "vendor": scan.vendor,
            "scan_time": scan.scan_time.isoformat(),
            "total_vulns": scan.total_vulns,
            "critical": scan.critical,
            "high": scan.high,
            "medium": scan.medium,
            "low": scan.low,
            "unknown": scan.unknown,
            "error": scan.error,
            "vulnerabilities": [
                {
                    "cve_id": v.cve_id,
                    "severity": v.severity,
                    "package": v.package,
                    "installed_version": v.installed_version,
                    "fixed_version": v.fixed_version,
                    "title": v.title
                }
                for v in scan.vulnerabilities
            ]
        }

    recommendation = get_recommendation(result)

    data = {
        "image_name": result.image_name,
        "generated_at": datetime.now().isoformat(),
        "recommendation": {
            "winner": recommendation.winner,
            "headline": recommendation.headline,
            "bullets": recommendation.bullets,
            "confidence": recommendation.confidence
        },
        "summary": result.get_summary(),
        "chainguard_scan": scan_to_dict(result.cg_result),
        "dhi_scan": scan_to_dict(result.dhi_result),
        "cg_unique_cves": result.cg_unique_cves,
        "dhi_unique_cves": result.dhi_unique_cves,
        "common_cves": result.common_cves
    }

    return json.dumps(data, indent=2)


def get_severity_order() -> List[str]:
    """Return severity levels in order of importance."""
    return ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def sort_vulnerabilities(vulns: List[Vulnerability]) -> List[Vulnerability]:
    """Sort vulnerabilities by severity (Critical first)."""
    severity_order = get_severity_order()
    return sorted(
        vulns,
        key=lambda v: severity_order.index(v.severity) if v.severity in severity_order else 99
    )
