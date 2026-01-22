"""VulnCompare: Compare vulnerability scans between Chainguard and Docker Hardened Images."""

import streamlit as st
from datetime import datetime, timezone
from typing import List, Optional

from src.models import ComparisonResult, ImageEntry, ScanResult, Vulnerability, MacroComparisonResult
from src.catalog import get_all_image_entries, search_images, update_availability
from src.comparison import run_comparison, export_comparison_csv, get_vulnerabilities_by_cve
from src.docker_utils import check_docker_running, get_docker_login_status, docker_login
from src.recommendation import (
    get_recommendation,
    generate_summary_text,
    export_comparison_json,
    sort_vulnerabilities
)
from src.mappings import get_all_canonical_names
from src.cache import (
    is_deployed_mode,
    get_cached_comparison,
    get_all_cached_images,
    get_last_updated,
    get_cache_timestamp,
    save_comparison_to_cache
)
from src.macro_comparison import (
    compute_macro_comparison,
    export_macro_comparison_csv,
    export_macro_comparison_json
)

# Page config
st.set_page_config(
    page_title="VulnCompare",
    page_icon="🔒",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# Minimal CSS
st.markdown("""
<style>
    .block-container { padding-top: 1.5rem; max-width: 900px; }
    .stButton > button { width: 100%; }
    div[data-testid="stExpander"] { border: none; }

    /* Navigation pills */
    .nav-container {
        display: flex;
        gap: 0.5rem;
        margin-bottom: 1.5rem;
        border-bottom: 1px solid #e0e0e0;
        padding-bottom: 1rem;
    }
    .nav-pill {
        padding: 0.5rem 1.5rem;
        border-radius: 20px;
        font-weight: 500;
        cursor: pointer;
        border: 1px solid #e0e0e0;
        background: white;
        color: #666;
        text-decoration: none;
    }
    .nav-pill.active {
        background: #1f77b4;
        color: white;
        border-color: #1f77b4;
    }

    /* Image cards */
    .image-card {
        border: 1px solid #e8e8e8;
        border-radius: 8px;
        padding: 1rem;
        margin-bottom: 0.75rem;
        background: #fafafa;
    }
    .image-card:hover {
        border-color: #ccc;
        background: #f5f5f5;
    }
    .image-name {
        font-weight: 600;
        font-size: 1rem;
        margin-bottom: 0.25rem;
    }
    .image-category {
        color: #888;
        font-size: 0.8rem;
        margin-bottom: 0.5rem;
    }
    .availability-chip {
        display: inline-block;
        padding: 0.2rem 0.5rem;
        border-radius: 4px;
        font-size: 0.75rem;
        margin-right: 0.5rem;
    }
    .chip-available {
        background: #d4edda;
        color: #155724;
    }
    .chip-unavailable {
        background: #f8d7da;
        color: #721c24;
    }

    /* Verdict card */
    .verdict-card {
        padding: 1rem 1.25rem;
        border-radius: 8px;
        margin-bottom: 1rem;
        border-left: 4px solid;
    }
    .verdict-headline {
        font-weight: 600;
        font-size: 1.1rem;
        margin-bottom: 0.5rem;
    }
    .verdict-bullets {
        margin: 0;
        padding-left: 1.25rem;
        color: #444;
    }
    .confidence-badge {
        display: inline-block;
        padding: 0.15rem 0.5rem;
        border-radius: 10px;
        font-size: 0.7rem;
        text-transform: uppercase;
        margin-left: 0.5rem;
    }

    /* Severity cards */
    .severity-card {
        text-align: center;
        padding: 0.75rem;
        border-radius: 6px;
        margin-bottom: 0.5rem;
    }
    .severity-count {
        font-size: 1.5rem;
        font-weight: 700;
    }
    .severity-label {
        font-size: 0.75rem;
        text-transform: uppercase;
        opacity: 0.8;
    }

    /* CVE rows */
    .cve-row {
        padding: 0.4rem 0;
        border-bottom: 1px solid #f0f0f0;
        font-size: 0.85rem;
    }
    .cve-row:last-child {
        border-bottom: none;
    }

    /* Delta bullets */
    .delta-list {
        background: #f8f9fa;
        border-radius: 6px;
        padding: 1rem 1.25rem;
        margin-bottom: 1rem;
    }
    .delta-item {
        padding: 0.3rem 0;
        color: #333;
    }
</style>
""", unsafe_allow_html=True)


# ============================================================================
# Session State Initialization
# ============================================================================

def init_session_state():
    """Initialize all session state variables."""
    defaults = {
        "page": "single_browse",  # single_browse, single_results, macro_browse, macro_results
        "selected_image": None,
        "comparison_result": None,
        "comparison_running": False,
        "comparison_logs": [],
        "comparison_error": None,
        "selected_images": set(),
        "macro_result": None,
        "filter_mode": "comparable",  # comparable, all
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


init_session_state()


# ============================================================================
# Navigation and Routing
# ============================================================================

def navigate_to(page: str, **kwargs):
    """Navigate to a page with optional parameters."""
    st.session_state.page = page
    for key, value in kwargs.items():
        st.session_state[key] = value
    st.rerun()


def render_nav():
    """Render header and navigation."""
    # Title
    st.markdown("## VulnCompare")
    st.caption("Compare vulnerability scans between Chainguard and Docker Hardened Images")

    # Navigation tabs
    is_single = st.session_state.page.startswith("single")
    is_macro = st.session_state.page.startswith("macro")

    col1, col2, col3 = st.columns([1, 1, 2])

    with col1:
        if st.button(
            "Single Compare",
            type="primary" if is_single else "secondary",
            use_container_width=True
        ):
            navigate_to("single_browse", comparison_result=None, selected_image=None)

    with col2:
        if st.button(
            "Macro Compare",
            type="primary" if is_macro else "secondary",
            use_container_width=True
        ):
            navigate_to("macro_browse", macro_result=None)

    st.markdown("")


# ============================================================================
# Helper Functions
# ============================================================================

def add_log(msg: str):
    """Add a log message."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    st.session_state.comparison_logs.append(f"[{timestamp}] {msg}")


def clear_logs():
    """Clear log messages."""
    st.session_state.comparison_logs = []


def format_age(dt: datetime) -> str:
    """Format a datetime as a human-readable age string."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    age_hours = (datetime.now(timezone.utc) - dt).total_seconds() / 3600
    if age_hours < 1:
        return f"{int(age_hours * 60)} minutes ago"
    elif age_hours < 24:
        return f"{int(age_hours)} hours ago"
    else:
        return f"{int(age_hours / 24)} days ago"


def get_severity_colors():
    """Return severity color mapping."""
    return {
        "CRITICAL": {"bg": "#fee2e2", "text": "#dc2626", "border": "#fca5a5"},
        "HIGH": {"bg": "#ffedd5", "text": "#ea580c", "border": "#fdba74"},
        "MEDIUM": {"bg": "#fef3c7", "text": "#d97706", "border": "#fcd34d"},
        "LOW": {"bg": "#dcfce7", "text": "#16a34a", "border": "#86efac"},
        "UNKNOWN": {"bg": "#f3f4f6", "text": "#6b7280", "border": "#d1d5db"},
    }


def count_vulns_without_fix(vulns: List[Vulnerability]) -> dict:
    """Count vulnerabilities without a fix version by severity."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for v in vulns:
        if not v.fixed_version and v.severity in counts:
            counts[v.severity] += 1
    return counts


# ============================================================================
# Single Browse Page
# ============================================================================

def render_single_browse():
    """Render the single image browse/search page."""
    deployed = is_deployed_mode()

    # Last updated and refresh
    col_updated, col_refresh = st.columns([3, 1])
    with col_updated:
        last_updated = get_last_updated()
        if last_updated:
            st.caption(f"Data last updated: {format_age(last_updated)}")
    with col_refresh:
        if not deployed:
            if st.button("Refresh", use_container_width=True, type="secondary"):
                refresh_catalogs()

    # Settings (local mode only)
    if not deployed:
        with st.expander("Settings", expanded=False):
            render_auth_settings()

    st.markdown("###")

    # Search
    search_query = st.text_input(
        "Search images",
        placeholder="Search images, for example redis, nginx, postgres",
        label_visibility="collapsed"
    )

    # Filter toggle
    filter_options = ["Comparable only", "All images"]
    selected_filter = st.radio(
        "Filter",
        filter_options,
        horizontal=True,
        label_visibility="collapsed",
        index=0 if st.session_state.filter_mode == "comparable" else 1
    )
    st.session_state.filter_mode = "comparable" if selected_filter == "Comparable only" else "all"

    st.markdown("###")

    # Get images
    if deployed:
        images = get_cached_images_as_entries(search_query)
    else:
        images = get_catalog_entries(search_query)

    # Apply filter
    if st.session_state.filter_mode == "comparable":
        images = [img for img in images if img.get("comparable", False)]

    # Render results
    if not images:
        render_empty_state()
    else:
        st.caption(f"Showing {len(images)} images")
        for img in images[:20]:
            render_image_card(img, deployed)
        if len(images) > 20:
            st.caption(f"Showing first 20 of {len(images)} images. Use search to narrow results.")


def get_cached_images_as_entries(search_query: str) -> List[dict]:
    """Get cached images formatted as entry dicts."""
    cached_images = get_all_cached_images()
    if search_query:
        cached_images = [img for img in cached_images if search_query.lower() in img.lower()]

    entries = []
    for name in sorted(cached_images):
        entries.append({
            "name": name,
            "category": "",
            "cg_available": True,
            "dhi_available": True,
            "comparable": True,
            "cached_time": get_cache_timestamp(name)
        })
    return entries


def get_catalog_entries(search_query: str) -> List[dict]:
    """Get catalog entries formatted as entry dicts."""
    if search_query:
        raw_entries = search_images(search_query)
    else:
        raw_entries = get_all_image_entries()

    entries = []
    for e in sorted(raw_entries, key=lambda x: (not x.available_in_both, x.canonical_name)):
        entries.append({
            "name": e.canonical_name,
            "category": e.category,
            "cg_available": e.cg_available,
            "dhi_available": e.dhi_available,
            "comparable": e.cg_available and e.dhi_available,
            "cached_time": get_cache_timestamp(e.canonical_name)
        })
    return entries


def render_image_card(img: dict, deployed: bool):
    """Render a compact image card."""
    col_info, col_action = st.columns([3, 1])

    with col_info:
        st.markdown(f"**{img['name']}**")

        # Category if available
        if img.get("category"):
            st.caption(img["category"])

        # Availability chips
        chips_html = ""
        if img["cg_available"]:
            chips_html += '<span class="availability-chip chip-available">Chainguard</span>'
        else:
            chips_html += '<span class="availability-chip chip-unavailable">Chainguard</span>'

        if img["dhi_available"]:
            chips_html += '<span class="availability-chip chip-available">Docker Hardened</span>'
        else:
            chips_html += '<span class="availability-chip chip-unavailable">Docker Hardened</span>'

        st.markdown(chips_html, unsafe_allow_html=True)

        # Cache timestamp
        if img.get("cached_time"):
            st.caption(f"Scanned {format_age(img['cached_time'])}")

    with col_action:
        if img["comparable"]:
            if st.button("Compare", key=f"cmp_{img['name']}", type="primary", use_container_width=True):
                start_single_comparison(img["name"], deployed)
        else:
            available_in = "Chainguard" if img["cg_available"] else "Docker Hardened"
            st.caption(f"Only in {available_in}")

    st.divider()


def render_empty_state():
    """Render empty state with suggestions."""
    st.info("No images found matching your search.")
    st.markdown("**Try searching for:**")

    suggestions = ["redis", "nginx", "postgres"]
    cols = st.columns(3)
    for i, suggestion in enumerate(suggestions):
        with cols[i]:
            if st.button(suggestion, use_container_width=True):
                st.session_state.search_suggestion = suggestion
                st.rerun()


def start_single_comparison(image_name: str, deployed: bool):
    """Start comparison and navigate to results."""
    if deployed:
        # Load from cache
        result = get_cached_comparison(image_name)
        if result:
            navigate_to("single_results", comparison_result=result, selected_image=image_name)
        else:
            st.error(f"No cached results for {image_name}")
    else:
        # Run live comparison
        st.session_state.selected_image = image_name
        st.session_state.comparison_running = True
        st.session_state.comparison_error = None
        clear_logs()
        navigate_to("single_results")


# ============================================================================
# Single Results Page
# ============================================================================

def render_single_results():
    """Render the single image results page."""
    # Handle running comparison
    if st.session_state.comparison_running:
        render_comparison_progress()
        return

    result = st.session_state.comparison_result
    if result is None:
        st.warning("No comparison results available.")
        if st.button("Back to search"):
            navigate_to("single_browse")
        return

    # Back button and title
    col_back, col_title = st.columns([1, 3])
    with col_back:
        if st.button("← Back"):
            navigate_to("single_browse", comparison_result=None, selected_image=None)
    with col_title:
        st.markdown(f"**Comparing: {result.image_name}**")

    # Image references
    if result.cg_result and result.dhi_result:
        st.caption(
            f"**Chainguard:** {result.cg_result.image} | "
            f"**DHI:** {result.dhi_result.image} | "
            f"Scanned: {result.cg_result.scan_time.strftime('%Y-%m-%d %H:%M')} UTC"
        )

    # Check for errors
    has_errors = False
    if result.cg_result and result.cg_result.has_error:
        has_errors = True
    if result.dhi_result and result.dhi_result.has_error:
        has_errors = True

    if has_errors:
        st.warning("Comparison completed with errors. Results may be incomplete.")
        with st.expander("View errors", expanded=True):
            if result.cg_result and result.cg_result.has_error:
                st.error(f"Chainguard: {result.cg_result.error}")
            if result.dhi_result and result.dhi_result.has_error:
                st.error(f"DHI: {result.dhi_result.error}")
        return

    # Recommendation verdict
    recommendation = get_recommendation(result)
    render_verdict(recommendation)

    # Differences that matter
    render_delta_summary(result)

    # Severity breakdown
    render_severity_cards(result)

    # Unique CVEs
    render_unique_cves(result)

    # Drill downs
    render_drill_downs(result)

    # Exports
    render_exports(result, recommendation)

    # Technical details
    render_technical_section(result)


def render_comparison_progress():
    """Render comparison progress."""
    image_name = st.session_state.selected_image
    st.markdown(f"### Scanning: {image_name}")

    with st.status("Running comparison...", expanded=True) as status:
        try:
            add_log(f"Starting comparison for {image_name}")
            st.write("Pulling images from registries...")
            st.write("Scanning with Trivy...")

            result = run_comparison(image_name, progress_callback=add_log)

            st.write("Computing differences...")
            add_log("Comparison complete")

            save_comparison_to_cache(result)
            add_log("Results cached")

            st.session_state.comparison_result = result
            st.session_state.comparison_running = False
            status.update(label="Comparison complete", state="complete", expanded=False)

        except Exception as e:
            st.session_state.comparison_error = str(e)
            st.session_state.comparison_running = False
            add_log(f"Error: {e}")
            status.update(label="Comparison failed", state="error")

    if st.session_state.comparison_error:
        st.error(f"Error: {st.session_state.comparison_error}")
        if st.button("Back to search"):
            navigate_to("single_browse")
    else:
        st.rerun()


def render_verdict(recommendation):
    """Render the recommendation verdict card."""
    colors = {
        "chainguard": {"bg": "#ecfdf5", "border": "#10b981"},
        "dhi": {"bg": "#eff6ff", "border": "#3b82f6"},
        "none": {"bg": "#fffbeb", "border": "#f59e0b"},
    }

    conf_colors = {
        "high": {"bg": "#dcfce7", "text": "#166534"},
        "medium": {"bg": "#fef3c7", "text": "#92400e"},
        "low": {"bg": "#f3f4f6", "text": "#6b7280"},
    }

    c = colors.get(recommendation.winner, colors["none"])
    cc = conf_colors.get(recommendation.confidence, conf_colors["low"])

    bullets_html = "".join(f"<li>{b}</li>" for b in recommendation.bullets)

    st.markdown(f"""
    <div class="verdict-card" style="background: {c['bg']}; border-left-color: {c['border']};">
        <div class="verdict-headline">
            {recommendation.headline}
            <span class="confidence-badge" style="background: {cc['bg']}; color: {cc['text']};">
                {recommendation.confidence} confidence
            </span>
        </div>
        <ul class="verdict-bullets">{bullets_html}</ul>
    </div>
    """, unsafe_allow_html=True)


def render_delta_summary(result: ComparisonResult):
    """Render the key differences summary."""
    if not result.cg_result or not result.dhi_result:
        return

    cg = result.cg_result
    dhi = result.dhi_result

    deltas = []

    # Critical delta
    crit_diff = dhi.critical - cg.critical
    if crit_diff != 0:
        winner = "Chainguard" if crit_diff > 0 else "DHI"
        deltas.append(f"**Critical:** {winner} has {abs(crit_diff)} fewer")
    else:
        deltas.append(f"**Critical:** Both have {cg.critical}")

    # High delta
    high_diff = dhi.high - cg.high
    if high_diff != 0:
        winner = "Chainguard" if high_diff > 0 else "DHI"
        deltas.append(f"**High:** {winner} has {abs(high_diff)} fewer")
    else:
        deltas.append(f"**High:** Both have {cg.high}")

    # Total delta
    total_diff = dhi.total_vulns - cg.total_vulns
    if total_diff != 0:
        winner = "Chainguard" if total_diff > 0 else "DHI"
        deltas.append(f"**Total:** {winner} has {abs(total_diff)} fewer vulnerabilities")
    else:
        deltas.append(f"**Total:** Both have {cg.total_vulns} vulnerabilities")

    # Unique CVEs
    cg_unique = len(result.cg_unique_cves)
    dhi_unique = len(result.dhi_unique_cves)
    deltas.append(f"**Unique CVEs:** {cg_unique} only in Chainguard, {dhi_unique} only in DHI")

    # No-fix analysis
    if dhi.vulnerabilities:
        dhi_no_fix = count_vulns_without_fix(dhi.vulnerabilities)
        if dhi_no_fix["HIGH"] > 0 or dhi_no_fix["CRITICAL"] > 0:
            no_fix_parts = []
            if dhi_no_fix["CRITICAL"] > 0:
                no_fix_parts.append(f"{dhi_no_fix['CRITICAL']} Critical")
            if dhi_no_fix["HIGH"] > 0:
                no_fix_parts.append(f"{dhi_no_fix['HIGH']} High")
            deltas.append(f"**DHI unfixed:** {', '.join(no_fix_parts)} with no fix available")

    if cg.vulnerabilities:
        cg_no_fix = count_vulns_without_fix(cg.vulnerabilities)
        if cg_no_fix["HIGH"] > 0 or cg_no_fix["CRITICAL"] > 0:
            no_fix_parts = []
            if cg_no_fix["CRITICAL"] > 0:
                no_fix_parts.append(f"{cg_no_fix['CRITICAL']} Critical")
            if cg_no_fix["HIGH"] > 0:
                no_fix_parts.append(f"{cg_no_fix['HIGH']} High")
            deltas.append(f"**Chainguard unfixed:** {', '.join(no_fix_parts)} with no fix available")

    st.markdown("#### Differences That Matter")
    delta_html = "".join(f'<div class="delta-item">• {d}</div>' for d in deltas[:5])
    st.markdown(f'<div class="delta-list">{delta_html}</div>', unsafe_allow_html=True)


def render_severity_cards(result: ComparisonResult):
    """Render severity breakdown as cards."""
    if not result.cg_result or not result.dhi_result:
        return

    st.markdown("#### Severity Breakdown")

    colors = get_severity_colors()
    cg = result.cg_result
    dhi = result.dhi_result

    col_cg, col_dhi = st.columns(2)

    with col_cg:
        st.markdown("**Chainguard**")
        render_severity_card_group(cg, colors)
        st.markdown(f"**Total: {cg.total_vulns}**")

    with col_dhi:
        st.markdown("**Docker Hardened**")
        render_severity_card_group(dhi, colors)
        st.markdown(f"**Total: {dhi.total_vulns}**")


def render_severity_card_group(scan: ScanResult, colors: dict):
    """Render a group of severity cards for one vendor."""
    for sev, count in [("CRITICAL", scan.critical), ("HIGH", scan.high),
                        ("MEDIUM", scan.medium), ("LOW", scan.low)]:
        c = colors[sev]
        st.markdown(f"""
        <div class="severity-card" style="background: {c['bg']}; border: 1px solid {c['border']};">
            <div class="severity-count" style="color: {c['text']};">{count}</div>
            <div class="severity-label" style="color: {c['text']};">{sev}</div>
        </div>
        """, unsafe_allow_html=True)


def render_unique_cves(result: ComparisonResult):
    """Render unique CVEs section."""
    st.markdown("#### Unique Vulnerabilities")

    col_cg, col_dhi = st.columns(2)

    with col_cg:
        st.markdown(f"**Only in Chainguard ({len(result.cg_unique_cves)})**")
        if result.cg_unique_cves and result.cg_result:
            vulns = get_vulnerabilities_by_cve(result, result.cg_unique_cves, "chainguard")
            vulns = sort_vulnerabilities(vulns)[:10]
            render_cve_list(vulns)
            if len(result.cg_unique_cves) > 10:
                with st.expander(f"Show all {len(result.cg_unique_cves)}"):
                    all_vulns = get_vulnerabilities_by_cve(result, result.cg_unique_cves, "chainguard")
                    render_cve_list(sort_vulnerabilities(all_vulns))
        else:
            st.caption("None")

    with col_dhi:
        st.markdown(f"**Only in Docker Hardened ({len(result.dhi_unique_cves)})**")
        if result.dhi_unique_cves and result.dhi_result:
            vulns = get_vulnerabilities_by_cve(result, result.dhi_unique_cves, "dhi")
            vulns = sort_vulnerabilities(vulns)[:10]
            render_cve_list(vulns)
            if len(result.dhi_unique_cves) > 10:
                with st.expander(f"Show all {len(result.dhi_unique_cves)}"):
                    all_vulns = get_vulnerabilities_by_cve(result, result.dhi_unique_cves, "dhi")
                    render_cve_list(sort_vulnerabilities(all_vulns))
        else:
            st.caption("None")


def render_cve_list(vulns: List[Vulnerability]):
    """Render a compact CVE list."""
    colors = get_severity_colors()
    for v in vulns:
        c = colors.get(v.severity, colors["UNKNOWN"])
        fix_indicator = "✓" if v.fixed_version else "✗"
        fix_color = "#16a34a" if v.fixed_version else "#dc2626"
        st.markdown(
            f'<div class="cve-row">'
            f'<span style="color: {c["text"]};">●</span> '
            f'<strong>{v.cve_id}</strong> '
            f'<span style="color: #666;">{v.package}</span> '
            f'<span style="color: {fix_color}; font-size: 0.8rem;">{fix_indicator} fix</span>'
            f'</div>',
            unsafe_allow_html=True
        )


def render_drill_downs(result: ComparisonResult):
    """Render drill-down expanders."""
    st.markdown("#### Detailed Lists")

    with st.expander(f"All Chainguard CVEs ({result.cg_result.total_vulns if result.cg_result else 0})", expanded=False):
        if result.cg_result and result.cg_result.vulnerabilities:
            render_vuln_table(result.cg_result.vulnerabilities)
        else:
            st.caption("No vulnerabilities found")

    with st.expander(f"All Docker Hardened CVEs ({result.dhi_result.total_vulns if result.dhi_result else 0})", expanded=False):
        if result.dhi_result and result.dhi_result.vulnerabilities:
            render_vuln_table(result.dhi_result.vulnerabilities)
        else:
            st.caption("No vulnerabilities found")

    with st.expander(f"Common CVEs ({len(result.common_cves)})", expanded=False):
        if result.common_cves and result.cg_result:
            vulns = get_vulnerabilities_by_cve(result, result.common_cves, "chainguard")
            render_vuln_table(vulns)
        else:
            st.caption("No common vulnerabilities")


def render_vuln_table(vulns: List[Vulnerability]):
    """Render a vulnerability table."""
    vulns = sort_vulnerabilities(vulns)

    sev_icons = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🟢",
        "UNKNOWN": "⚪"
    }

    for v in vulns[:50]:
        icon = sev_icons.get(v.severity, "⚪")
        title = v.title[:60] + "..." if len(v.title) > 60 else v.title
        fix = f"Fixed: {v.fixed_version}" if v.fixed_version else "No fix"
        st.markdown(f"{icon} **{v.cve_id}** `{v.package}` {title}")
        st.caption(f"   {v.installed_version} | {fix}")

    if len(vulns) > 50:
        st.caption(f"Showing first 50 of {len(vulns)} vulnerabilities")


def render_exports(result: ComparisonResult, recommendation):
    """Render export buttons."""
    st.markdown("#### Export")

    col_csv, col_json, col_summary = st.columns(3)

    with col_csv:
        csv_data = export_comparison_csv(result)
        st.download_button(
            "CSV",
            data=csv_data,
            file_name=f"vulncompare_{result.image_name}_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
            use_container_width=True
        )

    with col_json:
        json_data = export_comparison_json(result)
        st.download_button(
            "JSON",
            data=json_data,
            file_name=f"vulncompare_{result.image_name}_{datetime.now().strftime('%Y%m%d')}.json",
            mime="application/json",
            use_container_width=True
        )

    with col_summary:
        summary_text = generate_summary_text(result, recommendation)
        st.download_button(
            "Summary",
            data=summary_text,
            file_name=f"vulncompare_{result.image_name}_summary.txt",
            mime="text/plain",
            use_container_width=True
        )


def render_technical_section(result: ComparisonResult):
    """Render technical details section."""
    with st.expander("Technical Details", expanded=False):
        st.markdown("**Scan Logs**")
        for log in st.session_state.comparison_logs:
            st.text(log)

        st.markdown("**Copy-Paste Format**")
        tabs = st.tabs(["Chainguard", "Docker Hardened", "Both"])

        with tabs[0]:
            if result.cg_result:
                st.code(format_scan_for_copy(result.cg_result), language="text")
            else:
                st.info("Not available")

        with tabs[1]:
            if result.dhi_result:
                st.code(format_scan_for_copy(result.dhi_result), language="text")
            else:
                st.info("Not available")

        with tabs[2]:
            st.code(format_comparison_for_copy(result), language="text")


def format_scan_for_copy(scan: ScanResult) -> str:
    """Format a single vendor's scan results as copy-paste text."""
    lines = []
    lines.append("=" * 80)
    lines.append(f"VULNERABILITY SCAN: {scan.image}")
    lines.append(f"Scanned: {scan.scan_time.strftime('%Y-%m-%d %H:%M:%S')} UTC")
    lines.append("=" * 80)
    lines.append("")

    summary = f"SUMMARY: {scan.total_vulns} vulnerabilities ({scan.critical} Critical, {scan.high} High, {scan.medium} Medium, {scan.low} Low)"
    lines.append(summary)
    lines.append("")

    if scan.total_vulns == 0:
        lines.append("NO VULNERABILITIES FOUND")
        lines.append("=" * 80)
        return "\n".join(lines)

    vulns_by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "UNKNOWN": []}
    for v in scan.vulnerabilities:
        sev = v.severity.upper() if v.severity else "UNKNOWN"
        if sev in vulns_by_severity:
            vulns_by_severity[sev].append(v)
        else:
            vulns_by_severity["UNKNOWN"].append(v)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]:
        vulns = vulns_by_severity[sev]
        if not vulns:
            continue

        vulns = sort_vulnerabilities(vulns)
        lines.append(f"{sev} SEVERITY ({len(vulns)}):")
        lines.append("-" * 80)

        for v in vulns:
            fixed = v.fixed_version if v.fixed_version else "N/A"
            lines.append(f"{v.cve_id} | {v.package} | {v.installed_version} | Fixed: {fixed}")
            if v.title:
                lines.append(f"  {v.title}")

        lines.append("")

    lines.append("=" * 80)
    return "\n".join(lines)


def format_comparison_for_copy(result: ComparisonResult) -> str:
    """Format both vendor scans as copy-paste text for comparison."""
    lines = []

    if result.cg_result:
        lines.append(format_scan_for_copy(result.cg_result))
    else:
        lines.append("=" * 80)
        lines.append("CHAINGUARD SCAN: Not available")
        lines.append("=" * 80)

    lines.append("")
    lines.append("--- vs ---")
    lines.append("")

    if result.dhi_result:
        lines.append(format_scan_for_copy(result.dhi_result))
    else:
        lines.append("=" * 80)
        lines.append("DOCKER HARDENED IMAGES SCAN: Not available")
        lines.append("=" * 80)

    return "\n".join(lines)


# ============================================================================
# Macro Browse Page
# ============================================================================

def render_macro_browse():
    """Render macro comparison image selection page."""
    st.caption("Select images to compare across both vendors")

    cached_images = get_all_cached_images()

    # Search filter
    search_query = st.text_input(
        "Filter images",
        placeholder="Filter images...",
        label_visibility="collapsed"
    )

    if search_query:
        cached_images = [img for img in cached_images if search_query.lower() in img.lower()]

    # Selection controls
    col_select, col_clear, col_count = st.columns([1, 1, 2])
    with col_select:
        if st.button("Select All", use_container_width=True):
            st.session_state.selected_images = set(cached_images)
            st.rerun()
    with col_clear:
        if st.button("Clear", use_container_width=True):
            st.session_state.selected_images = set()
            st.rerun()
    with col_count:
        st.markdown(f"**{len(st.session_state.selected_images)}** selected")

    st.divider()

    # Image list
    for image_name in sorted(cached_images):
        col_check, col_name, col_time = st.columns([1, 4, 2])

        is_selected = image_name in st.session_state.selected_images

        with col_check:
            if st.checkbox("", value=is_selected, key=f"macro_{image_name}", label_visibility="collapsed"):
                st.session_state.selected_images.add(image_name)
            else:
                st.session_state.selected_images.discard(image_name)

        with col_name:
            st.markdown(f"**{image_name}**")

        with col_time:
            cached_time = get_cache_timestamp(image_name)
            if cached_time:
                st.caption(f"Scanned {format_age(cached_time)}")

    st.divider()

    # Generate button
    if len(st.session_state.selected_images) >= 2:
        if st.button("Generate Macro Comparison", type="primary", use_container_width=True):
            selected_list = sorted(st.session_state.selected_images)
            st.session_state.macro_result = compute_macro_comparison(selected_list)
            navigate_to("macro_results")
    else:
        st.info("Select at least 2 images to generate comparison")


# ============================================================================
# Macro Results Page
# ============================================================================

def render_macro_results():
    """Render macro comparison results."""
    macro = st.session_state.macro_result
    if macro is None:
        st.warning("No macro comparison results available.")
        if st.button("Back to selection"):
            navigate_to("macro_browse")
        return

    # Back button and title
    col_back, col_title = st.columns([1, 3])
    with col_back:
        if st.button("← Back"):
            navigate_to("macro_browse", macro_result=None)
    with col_title:
        st.markdown(f"**Results: {macro.total_images} images compared**")

    # Errors
    if macro.images_with_errors:
        with st.expander(f"Excluded images ({len(macro.images_with_errors)})", expanded=False):
            for img in macro.images_with_errors:
                st.warning(f"{img}: Scan error or missing data")

    # Verdict
    render_macro_verdict(macro)

    # Aggregate severity
    render_macro_severity(macro)

    # Scoreboard
    render_macro_scoreboard(macro)

    # Per-image breakdown
    with st.expander("Per-Image Details", expanded=False):
        render_per_image_table(macro)

    # Exports
    render_macro_exports(macro)


def render_macro_verdict(macro: MacroComparisonResult):
    """Render macro verdict card."""
    if macro.cg_wins > macro.dhi_wins:
        bg = "#ecfdf5"
        border = "#10b981"
        headline = f"Chainguard leads in {macro.cg_wins} of {macro.total_images} images"
    elif macro.dhi_wins > macro.cg_wins:
        bg = "#eff6ff"
        border = "#3b82f6"
        headline = f"Docker Hardened leads in {macro.dhi_wins} of {macro.total_images} images"
    else:
        bg = "#fffbeb"
        border = "#f59e0b"
        headline = f"Vendors tied: Each leads in {macro.cg_wins} images"

    bullets = [
        f"Total vulnerabilities: Chainguard {macro.cg_total_vulns} vs DHI {macro.dhi_total_vulns}",
        f"Wins: Chainguard {macro.cg_wins} | DHI {macro.dhi_wins} | Ties {macro.ties}",
        f"Critical wins: Chainguard {macro.cg_critical_wins} vs DHI {macro.dhi_critical_wins}"
    ]

    bullets_html = "".join(f"<li>{b}</li>" for b in bullets)

    st.markdown(f"""
    <div class="verdict-card" style="background: {bg}; border-left-color: {border};">
        <div class="verdict-headline">{headline}</div>
        <ul class="verdict-bullets">{bullets_html}</ul>
    </div>
    """, unsafe_allow_html=True)


def render_macro_severity(macro: MacroComparisonResult):
    """Render aggregate severity breakdown."""
    st.markdown("#### Aggregate Severity")

    colors = get_severity_colors()

    col_header = st.columns([2, 2, 2, 2])
    col_header[0].markdown("**Severity**")
    col_header[1].markdown("**Chainguard**")
    col_header[2].markdown("**DHI**")
    col_header[3].markdown("**Delta**")

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cg = macro.cg_by_severity.get(sev, 0)
        dhi = macro.dhi_by_severity.get(sev, 0)
        diff = dhi - cg
        c = colors[sev]

        cols = st.columns([2, 2, 2, 2])
        cols[0].markdown(f'<span style="color: {c["text"]};">{sev}</span>', unsafe_allow_html=True)
        cols[1].markdown(str(cg))
        cols[2].markdown(str(dhi))

        if diff > 0:
            cols[3].markdown(f'<span style="color: #16a34a;">CG +{diff}</span>', unsafe_allow_html=True)
        elif diff < 0:
            cols[3].markdown(f'<span style="color: #dc2626;">DHI +{abs(diff)}</span>', unsafe_allow_html=True)
        else:
            cols[3].markdown("Equal")

    # Total
    cols = st.columns([2, 2, 2, 2])
    cols[0].markdown("**TOTAL**")
    cols[1].markdown(f"**{macro.cg_total_vulns}**")
    cols[2].markdown(f"**{macro.dhi_total_vulns}**")
    diff = macro.dhi_total_vulns - macro.cg_total_vulns
    if diff > 0:
        cols[3].markdown(f'<span style="color: #16a34a;">**CG +{diff}**</span>', unsafe_allow_html=True)
    elif diff < 0:
        cols[3].markdown(f'<span style="color: #dc2626;">**DHI +{abs(diff)}**</span>', unsafe_allow_html=True)
    else:
        cols[3].markdown("**Equal**")


def render_macro_scoreboard(macro: MacroComparisonResult):
    """Render win/loss scoreboard."""
    st.markdown("#### Scoreboard")

    col1, col2, col3 = st.columns(3)

    with col1:
        pct = f"{macro.cg_wins/macro.total_images*100:.0f}%" if macro.total_images > 0 else "0%"
        st.metric("Chainguard Wins", macro.cg_wins, pct)

    with col2:
        pct = f"{macro.dhi_wins/macro.total_images*100:.0f}%" if macro.total_images > 0 else "0%"
        st.metric("DHI Wins", macro.dhi_wins, pct)

    with col3:
        pct = f"{macro.ties/macro.total_images*100:.0f}%" if macro.total_images > 0 else "0%"
        st.metric("Ties", macro.ties, pct)

    # Visual bar
    if macro.total_images > 0:
        cg_pct = macro.cg_wins / macro.total_images * 100
        dhi_pct = macro.dhi_wins / macro.total_images * 100
        tie_pct = macro.ties / macro.total_images * 100

        st.markdown(f"""
        <div style="display: flex; height: 20px; border-radius: 4px; overflow: hidden; margin: 1rem 0;">
            <div style="width: {cg_pct}%; background: #10b981;" title="Chainguard"></div>
            <div style="width: {tie_pct}%; background: #f59e0b;" title="Ties"></div>
            <div style="width: {dhi_pct}%; background: #3b82f6;" title="DHI"></div>
        </div>
        <div style="display: flex; justify-content: space-between; font-size: 0.8rem; color: #666;">
            <span>Chainguard ({cg_pct:.0f}%)</span>
            <span>Ties ({tie_pct:.0f}%)</span>
            <span>DHI ({dhi_pct:.0f}%)</span>
        </div>
        """, unsafe_allow_html=True)


def render_per_image_table(macro: MacroComparisonResult):
    """Render per-image breakdown table."""
    sorted_results = sorted(
        macro.results,
        key=lambda r: (r.dhi_result.total_vulns - r.cg_result.total_vulns),
        reverse=True
    )

    cols = st.columns([3, 2, 2, 1])
    cols[0].markdown("**Image**")
    cols[1].markdown("**Chainguard**")
    cols[2].markdown("**DHI**")
    cols[3].markdown("**Winner**")

    for result in sorted_results:
        cg = result.cg_result
        dhi = result.dhi_result
        diff = dhi.total_vulns - cg.total_vulns

        if diff > 0:
            winner = "CG"
            w_color = "#10b981"
        elif diff < 0:
            winner = "DHI"
            w_color = "#3b82f6"
        else:
            winner = "="
            w_color = "#f59e0b"

        cols = st.columns([3, 2, 2, 1])
        cols[0].markdown(f"**{result.image_name}**")
        cols[1].markdown(f"{cg.critical}C/{cg.high}H/{cg.medium}M/{cg.low}L")
        cols[2].markdown(f"{dhi.critical}C/{dhi.high}H/{dhi.medium}M/{dhi.low}L")
        cols[3].markdown(f'<span style="color: {w_color}; font-weight: bold;">{winner}</span>', unsafe_allow_html=True)


def render_macro_exports(macro: MacroComparisonResult):
    """Render macro export buttons."""
    st.markdown("#### Export")

    col_csv, col_json = st.columns(2)

    with col_csv:
        csv_data = export_macro_comparison_csv(macro)
        st.download_button(
            "CSV",
            data=csv_data,
            file_name=f"vulncompare_macro_{macro.total_images}_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
            use_container_width=True
        )

    with col_json:
        json_data = export_macro_comparison_json(macro)
        st.download_button(
            "JSON",
            data=json_data,
            file_name=f"vulncompare_macro_{macro.total_images}_{datetime.now().strftime('%Y%m%d')}.json",
            mime="application/json",
            use_container_width=True
        )


# ============================================================================
# Auth Settings
# ============================================================================

def render_auth_settings():
    """Render authentication settings."""
    st.markdown("**Registry Authentication**")

    docker_running = check_docker_running()
    login_status = get_docker_login_status()

    col1, col2 = st.columns(2)

    with col1:
        if docker_running:
            st.success("Docker: Running")
        else:
            st.error("Docker: Not running")
            st.caption("Run: colima start")

    with col2:
        st.info("Chainguard: Public")

    if login_status.get("dhi.io"):
        st.success("Docker Hardened: Logged in")
    else:
        st.warning("Docker Hardened: Login required")
        st.caption("Run: docker login dhi.io")

        with st.form("dhi_login", clear_on_submit=True):
            col_user, col_pass = st.columns(2)
            with col_user:
                username = st.text_input("Username", key="login_user")
            with col_pass:
                password = st.text_input("Password", type="password", key="login_pass")

            if st.form_submit_button("Login"):
                if username and password:
                    success, msg = docker_login("dhi.io", username, password)
                    if success:
                        st.success("Login successful")
                        st.rerun()
                    else:
                        st.error(f"Login failed: {msg}")


def refresh_catalogs():
    """Refresh catalog availability for all images."""
    with st.status("Refreshing catalogs...", expanded=True) as status:
        names = get_all_canonical_names()
        total = len(names)
        both_count = 0

        for i, name in enumerate(names):
            st.write(f"Checking {name} ({i+1}/{total})")
            cg, dhi = update_availability(name)
            if cg and dhi:
                both_count += 1

        status.update(label=f"Found {both_count} images in both registries", state="complete")


# ============================================================================
# Main
# ============================================================================

def main():
    """Main application entry point."""
    deployed = is_deployed_mode()

    # Check Docker in local mode
    if not deployed:
        docker_running = check_docker_running()
        if not docker_running:
            st.error("Docker is not running. Start Docker first: colima start")
            return

    # Navigation
    render_nav()

    # Route to appropriate page
    page = st.session_state.page

    if page == "single_browse":
        render_single_browse()
    elif page == "single_results":
        render_single_results()
    elif page == "macro_browse":
        render_macro_browse()
    elif page == "macro_results":
        render_macro_results()
    else:
        render_single_browse()

    # Footer
    st.divider()
    cached_count = len(get_all_cached_images())
    if deployed:
        st.caption(f"{cached_count} cached images | [github.com/MicahFalde/vulncompare](https://github.com/MicahFalde/vulncompare)")
    else:
        st.caption(f"Local mode | {cached_count} cached images")


if __name__ == "__main__":
    main()
