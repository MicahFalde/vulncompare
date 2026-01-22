"""Scan result caching for VulnCompare."""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .models import ComparisonResult, ScanResult, Vulnerability

# Cache file path
CACHE_DIR = Path(__file__).parent.parent / "data"
CACHE_FILE = CACHE_DIR / "scan_cache.json"


def get_cache_path() -> Path:
    """Get the cache file path, creating directory if needed."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_FILE


def load_cache() -> Dict:
    """Load the scan cache from disk."""
    cache_path = get_cache_path()
    if cache_path.exists():
        try:
            with open(cache_path) as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {"images": {}, "last_updated": None}
    return {"images": {}, "last_updated": None}


def save_cache(cache: Dict):
    """Save the scan cache to disk."""
    cache_path = get_cache_path()
    cache["last_updated"] = datetime.now(timezone.utc).isoformat()
    with open(cache_path, "w") as f:
        json.dump(cache, f, indent=2)


def get_cached_comparison(image_name: str) -> Optional[ComparisonResult]:
    """Get a cached comparison result for an image."""
    cache = load_cache()
    if image_name not in cache.get("images", {}):
        return None

    data = cache["images"][image_name]
    return _dict_to_comparison(data)


def save_comparison_to_cache(result: ComparisonResult):
    """Save a comparison result to the cache."""
    cache = load_cache()
    if "images" not in cache:
        cache["images"] = {}

    cache["images"][result.image_name] = _comparison_to_dict(result)
    save_cache(cache)


def get_all_cached_images() -> List[str]:
    """Get list of all cached image names."""
    cache = load_cache()
    return list(cache.get("images", {}).keys())


def get_cache_timestamp(image_name: str) -> Optional[datetime]:
    """Get the scan timestamp for a cached image."""
    cache = load_cache()
    if image_name in cache.get("images", {}):
        ts = cache["images"][image_name].get("scan_timestamp")
        if ts:
            return datetime.fromisoformat(ts)
    return None


def get_last_updated() -> Optional[datetime]:
    """Get the last time the cache was updated."""
    cache = load_cache()
    ts = cache.get("last_updated")
    if ts:
        return datetime.fromisoformat(ts)
    return None


def clear_cache():
    """Clear all cached data."""
    cache_path = get_cache_path()
    if cache_path.exists():
        cache_path.unlink()


def _scan_to_dict(scan: Optional[ScanResult]) -> Optional[Dict]:
    """Convert ScanResult to dictionary."""
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
                "title": v.title,
                "description": v.description
            }
            for v in scan.vulnerabilities
        ]
    }


def _dict_to_scan(data: Optional[Dict]) -> Optional[ScanResult]:
    """Convert dictionary to ScanResult."""
    if data is None:
        return None
    return ScanResult(
        image=data["image"],
        vendor=data["vendor"],
        scan_time=datetime.fromisoformat(data["scan_time"]),
        total_vulns=data.get("total_vulns", 0),
        critical=data.get("critical", 0),
        high=data.get("high", 0),
        medium=data.get("medium", 0),
        low=data.get("low", 0),
        unknown=data.get("unknown", 0),
        error=data.get("error"),
        vulnerabilities=[
            Vulnerability(
                cve_id=v["cve_id"],
                severity=v["severity"],
                package=v["package"],
                installed_version=v["installed_version"],
                fixed_version=v.get("fixed_version"),
                title=v.get("title", ""),
                description=v.get("description", "")
            )
            for v in data.get("vulnerabilities", [])
        ]
    )


def _comparison_to_dict(result: ComparisonResult) -> Dict:
    """Convert ComparisonResult to dictionary."""
    return {
        "image_name": result.image_name,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "cg_result": _scan_to_dict(result.cg_result),
        "dhi_result": _scan_to_dict(result.dhi_result),
        "cg_unique_cves": result.cg_unique_cves,
        "dhi_unique_cves": result.dhi_unique_cves,
        "common_cves": result.common_cves
    }


def _dict_to_comparison(data: Dict) -> ComparisonResult:
    """Convert dictionary to ComparisonResult."""
    return ComparisonResult(
        image_name=data["image_name"],
        cg_result=_dict_to_scan(data.get("cg_result")),
        dhi_result=_dict_to_scan(data.get("dhi_result")),
        cg_unique_cves=data.get("cg_unique_cves", []),
        dhi_unique_cves=data.get("dhi_unique_cves", []),
        common_cves=data.get("common_cves", [])
    )


def is_deployed_mode() -> bool:
    """Check if running in deployed (read-only) mode."""
    # Check for Streamlit Cloud environment variable
    if os.environ.get("STREAMLIT_SHARING_MODE"):
        return True
    # Check if Docker is available
    import subprocess
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5
        )
        return result.returncode != 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return True
