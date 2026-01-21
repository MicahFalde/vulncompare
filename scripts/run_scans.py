#!/usr/bin/env python3
"""
Run vulnerability scans for all available images and update the cache.

This script is meant to be run locally (or via GitHub Actions) where Docker
and Trivy are available. It scans all images available in both Chainguard
and Docker Hardened Images, then saves results to the cache.

Usage:
    python scripts/run_scans.py [--images IMAGE1,IMAGE2,...] [--force]

Options:
    --images    Comma-separated list of specific images to scan (default: all)
    --force     Force re-scan even if cached results exist
    --dry-run   Show what would be scanned without actually scanning
"""

import argparse
import sys
from datetime import datetime
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.cache import (
    load_cache,
    save_comparison_to_cache,
    get_cache_timestamp,
    get_all_cached_images
)
from src.catalog import get_all_image_entries, update_availability
from src.comparison import run_comparison
from src.docker_utils import check_docker_running, get_docker_login_status
from src.mappings import get_all_canonical_names


def check_prerequisites() -> bool:
    """Check that Docker and credentials are available."""
    print("Checking prerequisites...")

    if not check_docker_running():
        print("ERROR: Docker is not running. Start it with: colima start")
        return False
    print("  Docker: OK")

    login_status = get_docker_login_status()
    if not login_status.get("dhi.io"):
        print("ERROR: Not logged into DHI. Run: docker login dhi.io")
        return False
    print("  DHI login: OK")

    print("  Chainguard: OK (public)")
    return True


def get_scannable_images(specific_images: list = None) -> list:
    """Get list of images that can be scanned (available in both registries)."""
    print("\nChecking image availability...")

    if specific_images:
        # Use specific images if provided
        entries = []
        for name in specific_images:
            print(f"  Checking {name}...")
            cg, dhi = update_availability(name)
            if cg and dhi:
                entries.append(name)
                print(f"    Available in both")
            else:
                print(f"    Not available in both (CG: {cg}, DHI: {dhi})")
        return entries

    # Otherwise, get all available images
    all_names = get_all_canonical_names()
    available = []

    for i, name in enumerate(all_names):
        print(f"  [{i+1}/{len(all_names)}] Checking {name}...", end=" ")
        cg, dhi = update_availability(name)
        if cg and dhi:
            available.append(name)
            print("OK")
        else:
            print(f"Skip (CG: {cg}, DHI: {dhi})")

    return available


def run_scan(image_name: str, force: bool = False) -> bool:
    """Run a scan for a single image."""
    # Check if already cached (unless force)
    if not force:
        cached_time = get_cache_timestamp(image_name)
        if cached_time:
            age_hours = (datetime.now() - cached_time).total_seconds() / 3600
            if age_hours < 24:
                print(f"  Skipping {image_name} (cached {age_hours:.1f}h ago)")
                return True

    print(f"  Scanning {image_name}...")

    try:
        result = run_comparison(
            image_name,
            progress_callback=lambda msg: print(f"    {msg}"),
            use_cache=False  # Always fresh scan
        )

        # Check for errors
        if result.cg_result and result.cg_result.has_error:
            print(f"    WARNING: Chainguard error: {result.cg_result.error}")
        if result.dhi_result and result.dhi_result.has_error:
            print(f"    WARNING: DHI error: {result.dhi_result.error}")

        # Save to cache
        save_comparison_to_cache(result)

        # Print summary
        cg_total = result.cg_result.total_vulns if result.cg_result else 0
        dhi_total = result.dhi_result.total_vulns if result.dhi_result else 0
        print(f"    Result: CG={cg_total} vulns, DHI={dhi_total} vulns")

        return True

    except Exception as e:
        print(f"    ERROR: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="Run vulnerability scans and update cache")
    parser.add_argument("--images", help="Comma-separated list of images to scan")
    parser.add_argument("--force", action="store_true", help="Force re-scan even if cached")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be scanned")
    args = parser.parse_args()

    print("=" * 60)
    print("VulnCompare Scan Runner")
    print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    # Check prerequisites
    if not args.dry_run and not check_prerequisites():
        sys.exit(1)

    # Get images to scan
    specific_images = args.images.split(",") if args.images else None
    scannable = get_scannable_images(specific_images)

    print(f"\nFound {len(scannable)} images available in both registries")

    if args.dry_run:
        print("\nDry run - would scan these images:")
        for img in scannable:
            print(f"  - {img}")
        return

    # Run scans
    print("\nRunning scans...")
    success_count = 0
    fail_count = 0

    for i, image_name in enumerate(scannable):
        print(f"\n[{i+1}/{len(scannable)}] {image_name}")
        if run_scan(image_name, force=args.force):
            success_count += 1
        else:
            fail_count += 1

    # Summary
    print("\n" + "=" * 60)
    print("Scan Complete")
    print(f"  Successful: {success_count}")
    print(f"  Failed: {fail_count}")
    print(f"  Cached images: {len(get_all_cached_images())}")
    print(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)

    if fail_count > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
