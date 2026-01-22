"""Data models for VulnCompare."""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class Vulnerability:
    """Represents a single vulnerability from a Trivy scan."""
    cve_id: str
    severity: str
    package: str
    installed_version: str
    fixed_version: Optional[str]
    title: str
    description: str = ""

    def __hash__(self):
        return hash(self.cve_id)

    def __eq__(self, other):
        if isinstance(other, Vulnerability):
            return self.cve_id == other.cve_id
        return False


@dataclass
class ScanResult:
    """Represents the results of a Trivy vulnerability scan."""
    image: str
    vendor: str  # "chainguard" or "dhi"
    scan_time: datetime
    total_vulns: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    unknown: int = 0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def has_error(self) -> bool:
        return self.error is not None


@dataclass
class ImageEntry:
    """Represents an image in the catalog."""
    canonical_name: str
    cg_image: Optional[str] = None
    dhi_image: Optional[str] = None
    cg_available: bool = False
    dhi_available: bool = False
    category: str = "other"

    @property
    def available_in_both(self) -> bool:
        return self.cg_available and self.dhi_available


@dataclass
class ComparisonResult:
    """Represents the comparison between CG and DHI scans for an image."""
    image_name: str
    cg_result: Optional[ScanResult]
    dhi_result: Optional[ScanResult]
    cg_unique_cves: List[str] = field(default_factory=list)
    dhi_unique_cves: List[str] = field(default_factory=list)
    common_cves: List[str] = field(default_factory=list)

    def get_summary(self) -> dict:
        """Returns severity summary with counts and differences."""
        summary = {}
        severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]

        for sev in severities:
            cg_count = 0
            dhi_count = 0

            if self.cg_result:
                cg_count = getattr(self.cg_result, sev.lower(), 0)
            if self.dhi_result:
                dhi_count = getattr(self.dhi_result, sev.lower(), 0)

            diff = dhi_count - cg_count
            if diff > 0:
                diff_text = f"CG -{diff} better"
            elif diff < 0:
                diff_text = f"DHI {-diff} better"
            else:
                diff_text = "Equal"

            summary[sev] = {
                "cg": cg_count,
                "dhi": dhi_count,
                "diff": diff,
                "diff_text": diff_text
            }

        # Add totals
        cg_total = self.cg_result.total_vulns if self.cg_result else 0
        dhi_total = self.dhi_result.total_vulns if self.dhi_result else 0
        diff = dhi_total - cg_total
        if diff > 0:
            diff_text = f"CG -{diff} better"
        elif diff < 0:
            diff_text = f"DHI {-diff} better"
        else:
            diff_text = "Equal"

        summary["TOTAL"] = {
            "cg": cg_total,
            "dhi": dhi_total,
            "diff": diff,
            "diff_text": diff_text
        }

        return summary


@dataclass
class MacroComparisonResult:
    """Aggregate comparison statistics across multiple images."""
    image_names: List[str]
    total_images: int
    images_with_errors: List[str]

    # Aggregate vulnerability counts
    cg_total_vulns: int
    dhi_total_vulns: int

    # By severity
    cg_by_severity: Dict[str, int]
    dhi_by_severity: Dict[str, int]

    # Win/loss statistics
    cg_wins: int
    dhi_wins: int
    ties: int

    # Per-severity wins
    cg_critical_wins: int
    dhi_critical_wins: int
    cg_high_wins: int
    dhi_high_wins: int

    # Individual results for drill-down
    results: List[ComparisonResult] = field(default_factory=list)
