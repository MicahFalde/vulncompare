"""Image catalog management."""

import json
import os
from pathlib import Path
from typing import List, Optional, Tuple

from .models import ImageEntry
from .mappings import (
    IMAGE_MAPPINGS,
    get_category,
    get_cg_full_image,
    get_dhi_full_image,
    get_all_canonical_names
)
from .docker_utils import check_image_exists


CATALOG_DIR = Path(__file__).parent.parent / "data" / "catalogs"


def load_catalog(vendor: str) -> dict:
    """Load a vendor's catalog from disk."""
    catalog_file = CATALOG_DIR / f"{vendor}.json"
    if catalog_file.exists():
        with open(catalog_file) as f:
            return json.load(f)
    return {}


def save_catalog(vendor: str, catalog: dict):
    """Save a vendor's catalog to disk."""
    os.makedirs(CATALOG_DIR, exist_ok=True)
    catalog_file = CATALOG_DIR / f"{vendor}.json"
    with open(catalog_file, "w") as f:
        json.dump(catalog, f, indent=2)


def check_availability(image_name: str, vendor: str) -> bool:
    """Check if an image is available in a vendor's registry."""
    if vendor == "chainguard":
        full_image = get_cg_full_image(image_name)
    else:
        full_image = get_dhi_full_image(image_name)

    if not full_image:
        return False

    return check_image_exists(full_image)


def update_availability(image_name: str, progress_callback=None) -> Tuple[bool, bool]:
    """
    Check availability of an image in both registries.

    Returns (cg_available, dhi_available).
    """
    if progress_callback:
        progress_callback(f"Checking {image_name} in Chainguard...")
    cg_available = check_availability(image_name, "chainguard")

    if progress_callback:
        progress_callback(f"Checking {image_name} in DHI...")
    dhi_available = check_availability(image_name, "dhi")

    # Update catalogs
    cg_catalog = load_catalog("chainguard")
    dhi_catalog = load_catalog("dhi")

    cg_catalog[image_name] = cg_available
    dhi_catalog[image_name] = dhi_available

    save_catalog("chainguard", cg_catalog)
    save_catalog("dhi", dhi_catalog)

    return cg_available, dhi_available


def get_image_entry(canonical_name: str) -> ImageEntry:
    """Get an ImageEntry for a canonical name, including cached availability."""
    cg_catalog = load_catalog("chainguard")
    dhi_catalog = load_catalog("dhi")

    return ImageEntry(
        canonical_name=canonical_name,
        cg_image=get_cg_full_image(canonical_name),
        dhi_image=get_dhi_full_image(canonical_name),
        cg_available=cg_catalog.get(canonical_name, False),
        dhi_available=dhi_catalog.get(canonical_name, False),
        category=get_category(canonical_name)
    )


def get_all_image_entries() -> List[ImageEntry]:
    """Get ImageEntry objects for all known images."""
    entries = []
    for name in get_all_canonical_names():
        entries.append(get_image_entry(name))
    return entries


def get_available_images(vendor: Optional[str] = None) -> List[ImageEntry]:
    """Get all images available in the specified vendor (or both if None)."""
    entries = get_all_image_entries()

    if vendor == "chainguard":
        return [e for e in entries if e.cg_available]
    elif vendor == "dhi":
        return [e for e in entries if e.dhi_available]
    else:
        return [e for e in entries if e.available_in_both]


def search_images(query: str) -> List[ImageEntry]:
    """Search for images by name."""
    query = query.lower()
    entries = get_all_image_entries()
    return [e for e in entries if query in e.canonical_name.lower()]


def refresh_all_availability(progress_callback=None) -> dict:
    """
    Refresh availability status for all known images.

    Returns summary of results.
    """
    results = {
        "total": 0,
        "cg_available": 0,
        "dhi_available": 0,
        "both_available": 0
    }

    names = get_all_canonical_names()
    results["total"] = len(names)

    for i, name in enumerate(names):
        if progress_callback:
            progress_callback(f"Checking {name} ({i+1}/{len(names)})...")

        cg, dhi = update_availability(name)

        if cg:
            results["cg_available"] += 1
        if dhi:
            results["dhi_available"] += 1
        if cg and dhi:
            results["both_available"] += 1

    return results
