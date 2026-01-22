"""Macro comparison aggregation logic for VulnCompare."""

import csv
import io
import json
from datetime import datetime, timezone
from typing import List

from .models import ComparisonResult, MacroComparisonResult
from .cache import get_cached_comparison


def compute_macro_comparison(image_names: List[str]) -> MacroComparisonResult:
    """
    Compute aggregate statistics across multiple cached comparisons.

    Args:
        image_names: List of canonical image names to aggregate

    Returns:
        MacroComparisonResult with aggregate statistics
    """
    results = []
    images_with_errors = []

    # Collect all valid results
    for name in image_names:
        result = get_cached_comparison(name)
        if result:
            if result.cg_result and result.dhi_result:
                if not result.cg_result.has_error and not result.dhi_result.has_error:
                    results.append(result)
                else:
                    images_with_errors.append(name)
            else:
                images_with_errors.append(name)
        else:
            images_with_errors.append(name)

    # Initialize counters
    cg_total = 0
    dhi_total = 0
    cg_by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    dhi_by_sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}

    cg_wins = 0
    dhi_wins = 0
    ties = 0

    cg_critical_wins = 0
    dhi_critical_wins = 0
    cg_high_wins = 0
    dhi_high_wins = 0

    for result in results:
        cg = result.cg_result
        dhi = result.dhi_result

        # Totals
        cg_total += cg.total_vulns
        dhi_total += dhi.total_vulns

        # By severity
        cg_by_sev["CRITICAL"] += cg.critical
        cg_by_sev["HIGH"] += cg.high
        cg_by_sev["MEDIUM"] += cg.medium
        cg_by_sev["LOW"] += cg.low
        cg_by_sev["UNKNOWN"] += cg.unknown

        dhi_by_sev["CRITICAL"] += dhi.critical
        dhi_by_sev["HIGH"] += dhi.high
        dhi_by_sev["MEDIUM"] += dhi.medium
        dhi_by_sev["LOW"] += dhi.low
        dhi_by_sev["UNKNOWN"] += dhi.unknown

        # Win/loss by total
        if cg.total_vulns < dhi.total_vulns:
            cg_wins += 1
        elif dhi.total_vulns < cg.total_vulns:
            dhi_wins += 1
        else:
            ties += 1

        # Win/loss by critical
        if cg.critical < dhi.critical:
            cg_critical_wins += 1
        elif dhi.critical < cg.critical:
            dhi_critical_wins += 1

        # Win/loss by high
        if cg.high < dhi.high:
            cg_high_wins += 1
        elif dhi.high < cg.high:
            dhi_high_wins += 1

    return MacroComparisonResult(
        image_names=image_names,
        total_images=len(results),
        images_with_errors=images_with_errors,
        cg_total_vulns=cg_total,
        dhi_total_vulns=dhi_total,
        cg_by_severity=cg_by_sev,
        dhi_by_severity=dhi_by_sev,
        cg_wins=cg_wins,
        dhi_wins=dhi_wins,
        ties=ties,
        cg_critical_wins=cg_critical_wins,
        dhi_critical_wins=dhi_critical_wins,
        cg_high_wins=cg_high_wins,
        dhi_high_wins=dhi_high_wins,
        results=results
    )


def export_macro_comparison_csv(macro: MacroComparisonResult) -> str:
    """Export macro comparison to CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow(["VulnCompare Macro Comparison Report"])
    writer.writerow([f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}"])
    writer.writerow([f"Images Analyzed: {macro.total_images}"])
    writer.writerow([])

    # Summary section
    writer.writerow(["AGGREGATE SUMMARY"])
    writer.writerow(["Metric", "Chainguard", "DHI", "Difference"])
    writer.writerow(["Total Vulnerabilities", macro.cg_total_vulns, macro.dhi_total_vulns,
                     macro.dhi_total_vulns - macro.cg_total_vulns])

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cg = macro.cg_by_severity.get(sev, 0)
        dhi = macro.dhi_by_severity.get(sev, 0)
        writer.writerow([sev, cg, dhi, dhi - cg])

    writer.writerow([])

    # Win/Loss section
    writer.writerow(["WIN/LOSS SUMMARY"])
    writer.writerow(["Chainguard Wins", macro.cg_wins])
    writer.writerow(["DHI Wins", macro.dhi_wins])
    writer.writerow(["Ties", macro.ties])
    writer.writerow([])

    # Per-image breakdown
    writer.writerow(["PER-IMAGE BREAKDOWN"])
    writer.writerow(["Image", "CG Total", "CG Crit", "CG High", "CG Med", "CG Low",
                     "DHI Total", "DHI Crit", "DHI High", "DHI Med", "DHI Low", "Winner"])

    for result in macro.results:
        cg = result.cg_result
        dhi = result.dhi_result
        diff = dhi.total_vulns - cg.total_vulns
        winner = "Chainguard" if diff > 0 else ("DHI" if diff < 0 else "Tie")

        writer.writerow([
            result.image_name,
            cg.total_vulns, cg.critical, cg.high, cg.medium, cg.low,
            dhi.total_vulns, dhi.critical, dhi.high, dhi.medium, dhi.low,
            winner
        ])

    return output.getvalue()


def export_macro_comparison_json(macro: MacroComparisonResult) -> str:
    """Export macro comparison to JSON string."""
    data = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_images": macro.total_images,
        "images_analyzed": macro.image_names,
        "images_with_errors": macro.images_with_errors,
        "aggregate": {
            "chainguard_total_vulnerabilities": macro.cg_total_vulns,
            "dhi_total_vulnerabilities": macro.dhi_total_vulns,
            "chainguard_by_severity": macro.cg_by_severity,
            "dhi_by_severity": macro.dhi_by_severity
        },
        "scoreboard": {
            "chainguard_wins": macro.cg_wins,
            "dhi_wins": macro.dhi_wins,
            "ties": macro.ties,
            "chainguard_critical_wins": macro.cg_critical_wins,
            "dhi_critical_wins": macro.dhi_critical_wins,
            "chainguard_high_wins": macro.cg_high_wins,
            "dhi_high_wins": macro.dhi_high_wins
        },
        "per_image": [
            {
                "image_name": r.image_name,
                "chainguard": {
                    "total": r.cg_result.total_vulns,
                    "critical": r.cg_result.critical,
                    "high": r.cg_result.high,
                    "medium": r.cg_result.medium,
                    "low": r.cg_result.low
                },
                "dhi": {
                    "total": r.dhi_result.total_vulns,
                    "critical": r.dhi_result.critical,
                    "high": r.dhi_result.high,
                    "medium": r.dhi_result.medium,
                    "low": r.dhi_result.low
                },
                "winner": "chainguard" if r.dhi_result.total_vulns > r.cg_result.total_vulns
                          else ("dhi" if r.cg_result.total_vulns > r.dhi_result.total_vulns else "tie")
            }
            for r in macro.results
        ]
    }

    return json.dumps(data, indent=2)
