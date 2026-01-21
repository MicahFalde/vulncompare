"""Trivy vulnerability scanner wrapper."""

import json
import os
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .models import ScanResult, Vulnerability


# Cache directory for scan results
CACHE_DIR = Path(__file__).parent.parent / "data" / "scans"


def run_trivy_scan(image: str, output_file: Optional[str] = None) -> tuple[bool, str]:
    """
    Run a Trivy vulnerability scan on an image.

    Returns (success, output_path_or_error).
    """
    if output_file is None:
        # Generate output filename based on image
        safe_name = image.replace("/", "_").replace(":", "_").replace(".", "_")
        output_file = str(CACHE_DIR / f"{safe_name}.json")

    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_file), exist_ok=True)

    cmd = [
        "trivy", "image",
        "--format", "json",
        "--vuln-type", "os,library",
        "--output", output_file,
        image
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=600  # 10 minute timeout for large images
        )
        if result.returncode == 0:
            return True, output_file
        else:
            error = result.stderr or result.stdout or "Unknown error"
            return False, error
    except subprocess.TimeoutExpired:
        return False, "Scan timed out"
    except Exception as e:
        return False, str(e)


def parse_trivy_json(json_path: str, image: str, vendor: str) -> ScanResult:
    """Parse Trivy JSON output into a ScanResult."""
    scan_time = datetime.now()

    try:
        with open(json_path) as f:
            data = json.load(f)
    except Exception as e:
        return ScanResult(
            image=image,
            vendor=vendor,
            scan_time=scan_time,
            error=f"Failed to parse scan results: {e}"
        )

    vulnerabilities = []
    severity_counts = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "unknown": 0
    }

    results = data.get("Results", [])
    for result in results:
        vulns = result.get("Vulnerabilities", [])
        for vuln in vulns:
            severity = vuln.get("Severity", "UNKNOWN").upper()
            severity_key = severity.lower()
            if severity_key in severity_counts:
                severity_counts[severity_key] += 1
            else:
                severity_counts["unknown"] += 1

            v = Vulnerability(
                cve_id=vuln.get("VulnerabilityID", "UNKNOWN"),
                severity=severity,
                package=vuln.get("PkgName", "unknown"),
                installed_version=vuln.get("InstalledVersion", "unknown"),
                fixed_version=vuln.get("FixedVersion"),
                title=vuln.get("Title", ""),
                description=vuln.get("Description", "")
            )
            vulnerabilities.append(v)

    total = sum(severity_counts.values())

    return ScanResult(
        image=image,
        vendor=vendor,
        scan_time=scan_time,
        total_vulns=total,
        critical=severity_counts["critical"],
        high=severity_counts["high"],
        medium=severity_counts["medium"],
        low=severity_counts["low"],
        unknown=severity_counts["unknown"],
        vulnerabilities=vulnerabilities
    )


def scan_image(image: str, vendor: str, use_cache: bool = True) -> ScanResult:
    """
    Scan an image and return the results.

    If use_cache is True, will return cached results if available.
    """
    # Determine cache path
    vendor_dir = "cg" if vendor == "chainguard" else "dhi"
    safe_name = image.replace("/", "_").replace(":", "_").replace(".", "_")
    cache_path = CACHE_DIR / vendor_dir / f"{safe_name}.json"

    # Check cache
    if use_cache and cache_path.exists():
        return parse_trivy_json(str(cache_path), image, vendor)

    # Ensure cache directory exists
    os.makedirs(cache_path.parent, exist_ok=True)

    # Run scan
    success, result = run_trivy_scan(image, str(cache_path))

    if success:
        return parse_trivy_json(result, image, vendor)
    else:
        return ScanResult(
            image=image,
            vendor=vendor,
            scan_time=datetime.now(),
            error=result
        )


def clear_cache(vendor: Optional[str] = None):
    """Clear cached scan results."""
    if vendor:
        vendor_dir = "cg" if vendor == "chainguard" else "dhi"
        cache_path = CACHE_DIR / vendor_dir
        if cache_path.exists():
            for f in cache_path.glob("*.json"):
                f.unlink()
    else:
        for vendor_dir in ["cg", "dhi"]:
            cache_path = CACHE_DIR / vendor_dir
            if cache_path.exists():
                for f in cache_path.glob("*.json"):
                    f.unlink()


def get_cached_scans() -> Dict[str, List[str]]:
    """Get list of cached scans by vendor."""
    cached = {"chainguard": [], "dhi": []}

    for vendor, vendor_dir in [("chainguard", "cg"), ("dhi", "dhi")]:
        cache_path = CACHE_DIR / vendor_dir
        if cache_path.exists():
            for f in cache_path.glob("*.json"):
                # Convert filename back to image name (approximate)
                cached[vendor].append(f.stem)

    return cached
