"""Comparison logic for vulnerability scan results."""

import csv
import io
from datetime import datetime
from typing import List, Optional

from .models import ComparisonResult, ScanResult, Vulnerability, ImageEntry
from .mappings import get_cg_full_image, get_dhi_full_image
from .docker_utils import pull_image, image_pulled_locally
from .trivy_scanner import scan_image


def compare_scans(cg_result: ScanResult, dhi_result: ScanResult) -> ComparisonResult:
    """Compare two scan results and compute differences."""
    # Get CVE sets
    cg_cves = {v.cve_id for v in cg_result.vulnerabilities}
    dhi_cves = {v.cve_id for v in dhi_result.vulnerabilities}

    cg_unique = sorted(cg_cves - dhi_cves)
    dhi_unique = sorted(dhi_cves - cg_cves)
    common = sorted(cg_cves & dhi_cves)

    return ComparisonResult(
        image_name=cg_result.image.split("/")[-1].split(":")[0],
        cg_result=cg_result,
        dhi_result=dhi_result,
        cg_unique_cves=cg_unique,
        dhi_unique_cves=dhi_unique,
        common_cves=common
    )


def run_comparison(
    canonical_name: str,
    progress_callback=None,
    use_cache: bool = True
) -> ComparisonResult:
    """
    Run a full comparison for an image.

    1. Pull both images (if not cached/local)
    2. Scan both with Trivy
    3. Compare results
    """
    cg_image = get_cg_full_image(canonical_name)
    dhi_image = get_dhi_full_image(canonical_name)

    cg_result = None
    dhi_result = None

    # Pull and scan Chainguard
    if cg_image:
        if progress_callback:
            progress_callback(f"Processing Chainguard image: {cg_image}")

        if not image_pulled_locally(cg_image):
            if progress_callback:
                progress_callback(f"Pulling {cg_image}...")
            success, msg = pull_image(cg_image)
            if not success:
                cg_result = ScanResult(
                    image=cg_image,
                    vendor="chainguard",
                    scan_time=datetime.now(),
                    error=f"Failed to pull image: {msg}"
                )

        if cg_result is None:
            if progress_callback:
                progress_callback(f"Scanning {cg_image} with Trivy...")
            cg_result = scan_image(cg_image, "chainguard", use_cache=use_cache)
    else:
        cg_result = ScanResult(
            image="N/A",
            vendor="chainguard",
            scan_time=datetime.now(),
            error="Image not mapped for Chainguard"
        )

    # Pull and scan DHI
    if dhi_image:
        if progress_callback:
            progress_callback(f"Processing DHI image: {dhi_image}")

        if not image_pulled_locally(dhi_image):
            if progress_callback:
                progress_callback(f"Pulling {dhi_image}...")
            success, msg = pull_image(dhi_image)
            if not success:
                dhi_result = ScanResult(
                    image=dhi_image,
                    vendor="dhi",
                    scan_time=datetime.now(),
                    error=f"Failed to pull image: {msg}"
                )

        if dhi_result is None:
            if progress_callback:
                progress_callback(f"Scanning {dhi_image} with Trivy...")
            dhi_result = scan_image(dhi_image, "dhi", use_cache=use_cache)
    else:
        dhi_result = ScanResult(
            image="N/A",
            vendor="dhi",
            scan_time=datetime.now(),
            error="Image not mapped for DHI"
        )

    return compare_scans(cg_result, dhi_result)


def get_vulnerabilities_by_cve(
    result: ComparisonResult,
    cve_list: List[str],
    source: str
) -> List[Vulnerability]:
    """Get full vulnerability details for a list of CVE IDs."""
    if source == "chainguard" and result.cg_result:
        vulns = result.cg_result.vulnerabilities
    elif source == "dhi" and result.dhi_result:
        vulns = result.dhi_result.vulnerabilities
    else:
        return []

    return [v for v in vulns if v.cve_id in cve_list]


def export_comparison_csv(result: ComparisonResult) -> str:
    """Export comparison result to CSV string."""
    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow([
        "Image",
        "Comparison Date",
        "",
        "",
        ""
    ])
    writer.writerow([
        result.image_name,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "",
        "",
        ""
    ])
    writer.writerow([])

    # Summary section
    writer.writerow(["VULNERABILITY SUMMARY"])
    writer.writerow(["Severity", "Chainguard", "DHI", "Difference"])

    summary = result.get_summary()
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN", "TOTAL"]:
        data = summary[sev]
        writer.writerow([
            sev,
            data["cg"],
            data["dhi"],
            data["diff_text"]
        ])

    writer.writerow([])

    # CVE Details
    writer.writerow(["CVE DETAILS"])
    writer.writerow([])

    # Chainguard unique
    writer.writerow([f"CVEs unique to Chainguard ({len(result.cg_unique_cves)}):"])
    writer.writerow(["CVE ID", "Severity", "Package", "Installed Version", "Fixed Version", "Title"])
    cg_vulns = get_vulnerabilities_by_cve(result, result.cg_unique_cves, "chainguard")
    for v in sorted(cg_vulns, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].index(x.severity) if x.severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] else 99):
        writer.writerow([
            v.cve_id,
            v.severity,
            v.package,
            v.installed_version,
            v.fixed_version or "N/A",
            v.title[:100] if v.title else ""
        ])

    writer.writerow([])

    # DHI unique
    writer.writerow([f"CVEs unique to DHI ({len(result.dhi_unique_cves)}):"])
    writer.writerow(["CVE ID", "Severity", "Package", "Installed Version", "Fixed Version", "Title"])
    dhi_vulns = get_vulnerabilities_by_cve(result, result.dhi_unique_cves, "dhi")
    for v in sorted(dhi_vulns, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].index(x.severity) if x.severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] else 99):
        writer.writerow([
            v.cve_id,
            v.severity,
            v.package,
            v.installed_version,
            v.fixed_version or "N/A",
            v.title[:100] if v.title else ""
        ])

    writer.writerow([])

    # Common CVEs
    writer.writerow([f"CVEs in both ({len(result.common_cves)}):"])
    writer.writerow(["CVE ID", "Severity", "Package", "Title"])
    common_vulns = get_vulnerabilities_by_cve(result, result.common_cves, "chainguard")
    for v in sorted(common_vulns, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"].index(x.severity) if x.severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"] else 99):
        writer.writerow([
            v.cve_id,
            v.severity,
            v.package,
            v.title[:100] if v.title else ""
        ])

    return output.getvalue()
