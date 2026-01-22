"""VulnCompare: Compare vulnerability scans between Chainguard and Docker Hardened Images."""

import streamlit as st
from datetime import datetime, timezone
from typing import List, Optional

from src.models import ComparisonResult, ImageEntry, Vulnerability, MacroComparisonResult
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

# Custom CSS for cleaner look
st.markdown("""
<style>
    .block-container { padding-top: 2rem; max-width: 900px; }
    .stButton > button { width: 100%; }
    div[data-testid="stExpander"] { border: none; }
    .severity-card {
        padding: 1rem;
        border-radius: 8px;
        text-align: center;
        margin-bottom: 0.5rem;
    }
    .verdict-card {
        padding: 1.5rem;
        border-radius: 12px;
        margin-bottom: 1rem;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if "comparison_result" not in st.session_state:
    st.session_state.comparison_result = None
if "selected_image" not in st.session_state:
    st.session_state.selected_image = None
if "comparison_running" not in st.session_state:
    st.session_state.comparison_running = False
if "comparison_logs" not in st.session_state:
    st.session_state.comparison_logs = []
if "comparison_error" not in st.session_state:
    st.session_state.comparison_error = None
# Macro comparison state
if "macro_mode" not in st.session_state:
    st.session_state.macro_mode = False
if "selected_images" not in st.session_state:
    st.session_state.selected_images = set()
if "macro_result" not in st.session_state:
    st.session_state.macro_result = None


def add_log(msg: str):
    """Add a log message."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    st.session_state.comparison_logs.append(f"[{timestamp}] {msg}")


def clear_logs():
    """Clear log messages."""
    st.session_state.comparison_logs = []


def render_header():
    """Render the minimal top header."""
    deployed = is_deployed_mode()
    cached_images = get_all_cached_images()

    # Title row with mode toggle
    col_title, col_toggle = st.columns([3, 1])
    with col_title:
        st.title("VulnCompare")
    with col_toggle:
        if deployed and len(cached_images) >= 2:
            mode_label = "Macro View" if st.session_state.macro_mode else "Single View"
            if st.button(mode_label, use_container_width=True):
                st.session_state.macro_mode = not st.session_state.macro_mode
                st.session_state.selected_images = set()
                st.session_state.macro_result = None
                st.session_state.comparison_result = None
                st.rerun()

    st.caption("Compare vulnerability scan results between Chainguard and Docker Hardened Images")

    # Show last updated timestamp
    last_updated = get_last_updated()
    if last_updated:
        # Make timezone-aware if naive (assume UTC)
        if last_updated.tzinfo is None:
            last_updated = last_updated.replace(tzinfo=timezone.utc)
        age_hours = (datetime.now(timezone.utc) - last_updated).total_seconds() / 3600
        if age_hours < 1:
            age_str = f"{int(age_hours * 60)} minutes ago"
        elif age_hours < 24:
            age_str = f"{int(age_hours)} hours ago"
        else:
            age_str = f"{int(age_hours / 24)} days ago"
        st.caption(f"Data last updated: {age_str}")

    # Settings expander (only show in local mode)
    if not deployed:
        with st.expander("Settings", expanded=False):
            render_auth_settings()
    else:
        mode_desc = "Macro comparison mode" if st.session_state.macro_mode else "Single image view"
        st.info(f"{mode_desc} | {len(cached_images)} cached images | [github.com/MicahFalde/vulncompare](https://github.com/MicahFalde/vulncompare)")


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
            st.caption("Run: `colima start`")

    with col2:
        st.info("Chainguard: Public (no login required)")

    if login_status.get("dhi.io"):
        st.success("Docker Hardened Images: Logged in")
    else:
        st.warning("Docker Hardened Images: Login required")
        st.caption("Run: `docker login dhi.io`")

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


def render_image_selector():
    """Render image selection section."""
    deployed = is_deployed_mode()

    st.markdown("### Select Image")

    # Search input
    search_query = st.text_input(
        "Search",
        placeholder="Search images, for example redis, nginx, postgres",
        label_visibility="collapsed"
    )

    if deployed:
        # Deployed mode: show cached images only
        cached_images = get_all_cached_images()
        if search_query:
            cached_images = [img for img in cached_images if search_query.lower() in img.lower()]

        st.caption(f"Showing {len(cached_images)} cached images")

        if len(cached_images) == 0:
            st.info("No cached scan results found.")
            return

        for image_name in sorted(cached_images)[:20]:
            render_cached_image_row(image_name)

        if len(cached_images) > 20:
            st.caption(f"Showing first 20 of {len(cached_images)} images. Use search to narrow results.")

    else:
        # Local mode: show live catalog
        col_filter, col_refresh = st.columns([3, 1])
        with col_filter:
            show_single_vendor = st.checkbox("Show single vendor images", value=False)
        with col_refresh:
            if st.button("Refresh catalogs", use_container_width=True):
                refresh_catalogs()

        # Get entries
        if search_query:
            entries = search_images(search_query)
        else:
            entries = get_all_image_entries()

        # Filter based on toggle
        if not show_single_vendor:
            entries = [e for e in entries if e.cg_available and e.dhi_available]

        # Sort: both available first, then by name
        entries = sorted(entries, key=lambda e: (not e.available_in_both, e.canonical_name))

        st.caption(f"Showing {len(entries)} images")

        if len(entries) == 0:
            st.info("No images found. Try refreshing catalogs or adjusting your search.")
            return

        # Render image list
        for entry in entries[:20]:  # Limit to 20 for performance
            render_image_row(entry)

        if len(entries) > 20:
            st.caption(f"Showing first 20 of {len(entries)} images. Use search to narrow results.")


def render_cached_image_row(image_name: str):
    """Render a cached image row (deployed mode)."""
    col_info, col_timestamp, col_action = st.columns([3, 2, 2])

    with col_info:
        st.markdown(f"**{image_name}**")

    with col_timestamp:
        cached_time = get_cache_timestamp(image_name)
        if cached_time:
            # Make timezone-aware if naive (assume UTC)
            if cached_time.tzinfo is None:
                cached_time = cached_time.replace(tzinfo=timezone.utc)
            age_hours = (datetime.now(timezone.utc) - cached_time).total_seconds() / 3600
            if age_hours < 24:
                st.caption(f"Scanned {int(age_hours)}h ago")
            else:
                st.caption(f"Scanned {int(age_hours/24)}d ago")

    with col_action:
        if st.button("View Results", key=f"view_{image_name}", type="primary", use_container_width=True):
            result = get_cached_comparison(image_name)
            if result:
                st.session_state.comparison_result = result
                st.session_state.selected_image = image_name
                st.rerun()

    st.divider()


def render_image_row(entry: ImageEntry):
    """Render a single image row."""
    col_info, col_avail, col_action = st.columns([3, 2, 2])

    with col_info:
        st.markdown(f"**{entry.canonical_name}**")
        st.caption(entry.category)

    with col_avail:
        cg_chip = "✓ Chainguard" if entry.cg_available else "✗ Chainguard"
        dhi_chip = "✓ Docker Hardened" if entry.dhi_available else "✗ Docker Hardened"

        if entry.cg_available:
            st.markdown(f"<span style='color: #28a745; font-size: 0.85em;'>{cg_chip}</span>", unsafe_allow_html=True)
        else:
            st.markdown(f"<span style='color: #dc3545; font-size: 0.85em;'>{cg_chip}</span>", unsafe_allow_html=True)

        if entry.dhi_available:
            st.markdown(f"<span style='color: #28a745; font-size: 0.85em;'>{dhi_chip}</span>", unsafe_allow_html=True)
        else:
            st.markdown(f"<span style='color: #dc3545; font-size: 0.85em;'>{dhi_chip}</span>", unsafe_allow_html=True)

    with col_action:
        if entry.cg_available and entry.dhi_available:
            if st.button("Compare", key=f"compare_{entry.canonical_name}", type="primary", use_container_width=True):
                start_comparison(entry.canonical_name)
        elif entry.cg_available or entry.dhi_available:
            vendor = "Chainguard" if entry.cg_available else "Docker Hardened"
            if st.button(f"Scan {vendor}", key=f"scan_{entry.canonical_name}", use_container_width=True):
                st.info(f"Single vendor scanning coming soon. Image available in {vendor} only.")

    st.divider()


def start_comparison(image_name: str):
    """Start the comparison process."""
    st.session_state.selected_image = image_name
    st.session_state.comparison_result = None
    st.session_state.comparison_running = True
    st.session_state.comparison_error = None
    clear_logs()
    st.rerun()


def render_comparison_progress():
    """Render comparison progress section."""
    if not st.session_state.comparison_running:
        return

    image_name = st.session_state.selected_image
    st.markdown(f"### Comparing: {image_name}")

    # Progress steps
    with st.status("Running comparison...", expanded=True) as status:
        try:
            add_log(f"Starting comparison for {image_name}")

            # Step 1: Pull images
            st.write("Step 1: Pull images")
            add_log("Pulling images from registries...")

            # Step 2 & 3: Scan
            st.write("Step 2: Scan Chainguard")
            st.write("Step 3: Scan Docker Hardened Images")

            # Run the actual comparison
            result = run_comparison(image_name, progress_callback=add_log)

            # Step 4: Compute differences
            st.write("Step 4: Compute differences")
            add_log("Computing vulnerability differences...")

            st.session_state.comparison_result = result
            st.session_state.comparison_running = False
            add_log("Comparison complete")

            # Save to cache for future use
            save_comparison_to_cache(result)
            add_log("Results cached")

            status.update(label="Comparison complete", state="complete", expanded=False)

        except Exception as e:
            st.session_state.comparison_error = str(e)
            st.session_state.comparison_running = False
            add_log(f"Error: {e}")
            status.update(label="Comparison failed", state="error")

    # Technical details expander
    with st.expander("Technical details", expanded=False):
        for log in st.session_state.comparison_logs:
            st.text(log)
        if st.session_state.comparison_error:
            st.error(f"Error: {st.session_state.comparison_error}")

    st.rerun()


def render_results():
    """Render comparison results section."""
    result = st.session_state.comparison_result
    if result is None:
        return

    # Check for errors
    has_errors = False
    if result.cg_result and result.cg_result.has_error:
        has_errors = True
    if result.dhi_result and result.dhi_result.has_error:
        has_errors = True

    st.markdown(f"### Results: {result.image_name}")

    # Technical details (errors, logs)
    with st.expander("Technical details", expanded=has_errors):
        if result.cg_result and result.cg_result.has_error:
            st.error(f"Chainguard error: {result.cg_result.error}")
        if result.dhi_result and result.dhi_result.has_error:
            st.error(f"Docker Hardened error: {result.dhi_result.error}")
        for log in st.session_state.comparison_logs:
            st.text(log)

    if has_errors:
        st.warning("Comparison completed with errors. Results may be incomplete.")
        return

    # Recommendation verdict
    recommendation = get_recommendation(result)
    render_verdict(recommendation)

    # Severity comparison
    render_severity_comparison(result)

    # Delta section
    render_delta_section(result)

    # Drill down expanders
    render_drill_down(result)

    # Export actions
    render_exports(result, recommendation)

    # New comparison button
    st.divider()
    if st.button("Start new comparison", use_container_width=True):
        st.session_state.comparison_result = None
        st.session_state.selected_image = None
        st.rerun()


def render_verdict(recommendation):
    """Render the recommendation verdict card."""
    if recommendation.winner == "chainguard":
        bg_color = "#d4edda"
        border_color = "#28a745"
    elif recommendation.winner == "dhi":
        bg_color = "#cce5ff"
        border_color = "#007bff"
    else:
        bg_color = "#fff3cd"
        border_color = "#ffc107"

    st.markdown(f"""
    <div style="background-color: {bg_color}; border-left: 4px solid {border_color}; padding: 1rem; border-radius: 4px; margin-bottom: 1rem;">
        <h4 style="margin: 0 0 0.5rem 0;">{recommendation.headline}</h4>
        <ul style="margin: 0; padding-left: 1.5rem;">
            {"".join(f"<li>{bullet}</li>" for bullet in recommendation.bullets)}
        </ul>
    </div>
    """, unsafe_allow_html=True)


def render_severity_comparison(result: ComparisonResult):
    """Render side by side severity cards."""
    summary = result.get_summary()

    st.markdown("**Severity Breakdown**")

    # Header row
    col_sev, col_cg, col_dhi = st.columns([1, 1, 1])
    with col_sev:
        st.markdown("**Severity**")
    with col_cg:
        st.markdown("**Chainguard**")
    with col_dhi:
        st.markdown("**Docker Hardened**")

    # Data rows
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        data = summary[sev]
        col_sev, col_cg, col_dhi = st.columns([1, 1, 1])

        # Color coding
        sev_colors = {
            "CRITICAL": "#dc3545",
            "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107",
            "LOW": "#28a745"
        }
        color = sev_colors.get(sev, "#6c757d")

        with col_sev:
            st.markdown(f"<span style='color: {color};'>{sev}</span>", unsafe_allow_html=True)
        with col_cg:
            cg_style = "font-weight: bold;" if data["diff"] > 0 else ""
            st.markdown(f"<span style='{cg_style}'>{data['cg']}</span>", unsafe_allow_html=True)
        with col_dhi:
            dhi_style = "font-weight: bold;" if data["diff"] < 0 else ""
            st.markdown(f"<span style='{dhi_style}'>{data['dhi']}</span>", unsafe_allow_html=True)

    # Total row
    total = summary["TOTAL"]
    col_sev, col_cg, col_dhi = st.columns([1, 1, 1])
    with col_sev:
        st.markdown("**TOTAL**")
    with col_cg:
        st.markdown(f"**{total['cg']}**")
    with col_dhi:
        st.markdown(f"**{total['dhi']}**")


def render_delta_section(result: ComparisonResult):
    """Render the delta section showing unique CVEs."""
    st.markdown("**Unique Vulnerabilities**")

    col_cg, col_dhi = st.columns(2)

    with col_cg:
        st.markdown(f"Only in Chainguard ({len(result.cg_unique_cves)})")
        if result.cg_unique_cves and result.cg_result:
            vulns = get_vulnerabilities_by_cve(result, result.cg_unique_cves, "chainguard")
            vulns = sort_vulnerabilities(vulns)[:10]
            for v in vulns:
                render_cve_chip(v)
            if len(result.cg_unique_cves) > 10:
                st.caption(f"+ {len(result.cg_unique_cves) - 10} more")
        else:
            st.caption("None")

    with col_dhi:
        st.markdown(f"Only in Docker Hardened ({len(result.dhi_unique_cves)})")
        if result.dhi_unique_cves and result.dhi_result:
            vulns = get_vulnerabilities_by_cve(result, result.dhi_unique_cves, "dhi")
            vulns = sort_vulnerabilities(vulns)[:10]
            for v in vulns:
                render_cve_chip(v)
            if len(result.dhi_unique_cves) > 10:
                st.caption(f"+ {len(result.dhi_unique_cves) - 10} more")
        else:
            st.caption("None")


def render_cve_chip(v: Vulnerability):
    """Render a single CVE as a compact chip."""
    sev_colors = {
        "CRITICAL": "#dc3545",
        "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107",
        "LOW": "#28a745",
        "UNKNOWN": "#6c757d"
    }
    color = sev_colors.get(v.severity, "#6c757d")
    st.markdown(
        f"<span style='color: {color}; font-size: 0.85em;'>● {v.cve_id}</span> "
        f"<span style='color: #666; font-size: 0.8em;'>{v.package}</span>",
        unsafe_allow_html=True
    )


def render_drill_down(result: ComparisonResult):
    """Render drill down expanders with full vulnerability lists."""
    st.markdown("**Detailed Vulnerability Lists**")

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

    for v in vulns[:50]:  # Limit for performance
        sev_colors = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "UNKNOWN": "⚪"
        }
        icon = sev_colors.get(v.severity, "⚪")
        title = v.title[:60] + "..." if len(v.title) > 60 else v.title
        st.markdown(f"{icon} **{v.cve_id}** ({v.severity}) `{v.package}` {title}")

    if len(vulns) > 50:
        st.caption(f"Showing first 50 of {len(vulns)} vulnerabilities")


def render_exports(result: ComparisonResult, recommendation):
    """Render export buttons."""
    st.markdown("**Export**")

    col_csv, col_json, col_copy = st.columns(3)

    with col_csv:
        csv_data = export_comparison_csv(result)
        st.download_button(
            "Export CSV",
            data=csv_data,
            file_name=f"vulncompare_{result.image_name}_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
            use_container_width=True
        )

    with col_json:
        json_data = export_comparison_json(result)
        st.download_button(
            "Export JSON",
            data=json_data,
            file_name=f"vulncompare_{result.image_name}_{datetime.now().strftime('%Y%m%d')}.json",
            mime="application/json",
            use_container_width=True
        )

    with col_copy:
        summary_text = generate_summary_text(result, recommendation)
        st.text_area("Summary (copy this)", summary_text, height=150, label_visibility="collapsed")


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

        status.update(label=f"Found {both_count} images available in both registries", state="complete")


def render_status_footer():
    """Render a subtle status footer."""
    deployed = is_deployed_mode()

    if deployed:
        cached_count = len(get_all_cached_images())
        st.caption(f"Deployed mode | {cached_count} cached images | github.com/mfalde/vulncompare")
    else:
        docker_running = check_docker_running()
        login_status = get_docker_login_status()

        status_parts = []
        if docker_running:
            status_parts.append("Docker: ✓")
        else:
            status_parts.append("Docker: ✗")

        status_parts.append("Chainguard: ✓")

        if login_status.get("dhi.io"):
            status_parts.append("DHI: ✓")
        else:
            status_parts.append("DHI: Login needed")

        status_parts.append("Local mode")

        st.caption(" | ".join(status_parts))


def render_macro_image_selector():
    """Render multi-select image selector for macro comparison."""
    st.markdown("### Select Images for Macro Comparison")

    cached_images = get_all_cached_images()

    # Search filter
    search_query = st.text_input(
        "Search",
        placeholder="Filter images...",
        label_visibility="collapsed",
        key="macro_search"
    )

    if search_query:
        cached_images = [img for img in cached_images if search_query.lower() in img.lower()]

    # Selection controls
    col_select_all, col_clear, col_count = st.columns([1, 1, 2])
    with col_select_all:
        if st.button("Select All", use_container_width=True):
            st.session_state.selected_images = set(cached_images)
            st.rerun()
    with col_clear:
        if st.button("Clear", use_container_width=True):
            st.session_state.selected_images = set()
            st.rerun()
    with col_count:
        selected_count = len(st.session_state.selected_images)
        st.markdown(f"**{selected_count}** images selected")

    st.divider()

    # Image list with checkboxes
    for image_name in sorted(cached_images):
        col_check, col_name, col_timestamp = st.columns([1, 3, 2])

        is_selected = image_name in st.session_state.selected_images

        with col_check:
            new_selected = st.checkbox("", value=is_selected, key=f"check_{image_name}", label_visibility="collapsed")
            if new_selected and not is_selected:
                st.session_state.selected_images.add(image_name)
            elif not new_selected and is_selected:
                st.session_state.selected_images.discard(image_name)

        with col_name:
            st.markdown(f"**{image_name}**")

        with col_timestamp:
            cached_time = get_cache_timestamp(image_name)
            if cached_time:
                if cached_time.tzinfo is None:
                    cached_time = cached_time.replace(tzinfo=timezone.utc)
                age_hours = (datetime.now(timezone.utc) - cached_time).total_seconds() / 3600
                if age_hours < 24:
                    st.caption(f"Scanned {int(age_hours)}h ago")
                else:
                    st.caption(f"Scanned {int(age_hours/24)}d ago")

    # Compare button
    st.divider()
    if len(st.session_state.selected_images) >= 2:
        if st.button("Generate Macro Comparison", type="primary", use_container_width=True):
            selected_list = sorted(st.session_state.selected_images)
            st.session_state.macro_result = compute_macro_comparison(selected_list)
            st.rerun()
    else:
        st.info("Select at least 2 images to generate macro comparison")


def render_macro_results():
    """Render macro comparison results."""
    macro = st.session_state.macro_result
    if macro is None:
        return

    st.markdown(f"### Macro Comparison: {macro.total_images} Images")

    # Error warning if any images had issues
    if macro.images_with_errors:
        with st.expander(f"Excluded images ({len(macro.images_with_errors)})", expanded=False):
            for img in macro.images_with_errors:
                st.warning(f"{img}: Scan error or missing data")

    # Overall verdict
    render_macro_verdict(macro)

    # Aggregate severity breakdown
    render_macro_severity_table(macro)

    # Win/Loss scoreboard
    render_macro_scoreboard(macro)

    # Per-image breakdown table
    render_per_image_table(macro)

    # Export section
    render_macro_exports(macro)

    # New comparison button
    st.divider()
    if st.button("New Macro Comparison", use_container_width=True):
        st.session_state.macro_result = None
        st.session_state.selected_images = set()
        st.rerun()


def render_macro_verdict(macro: MacroComparisonResult):
    """Render the overall macro verdict card."""
    # Determine overall winner
    if macro.cg_wins > macro.dhi_wins:
        bg_color = "#d4edda"
        border_color = "#28a745"
        headline = f"Chainguard leads in {macro.cg_wins} of {macro.total_images} images"
    elif macro.dhi_wins > macro.cg_wins:
        bg_color = "#cce5ff"
        border_color = "#007bff"
        headline = f"Docker Hardened leads in {macro.dhi_wins} of {macro.total_images} images"
    else:
        bg_color = "#fff3cd"
        border_color = "#ffc107"
        headline = f"Vendors tied: Each leads in {macro.cg_wins} images"

    bullets = [
        f"Total vulnerabilities: Chainguard {macro.cg_total_vulns} vs DHI {macro.dhi_total_vulns}",
        f"Chainguard wins: {macro.cg_wins} | DHI wins: {macro.dhi_wins} | Ties: {macro.ties}",
        f"Critical severity wins: CG {macro.cg_critical_wins} vs DHI {macro.dhi_critical_wins}"
    ]

    st.markdown(f"""
    <div style="background-color: {bg_color}; border-left: 4px solid {border_color};
                padding: 1rem; border-radius: 4px; margin-bottom: 1rem;">
        <h4 style="margin: 0 0 0.5rem 0;">{headline}</h4>
        <ul style="margin: 0; padding-left: 1.5rem;">
            {"".join(f"<li>{bullet}</li>" for bullet in bullets)}
        </ul>
    </div>
    """, unsafe_allow_html=True)


def render_macro_severity_table(macro: MacroComparisonResult):
    """Render aggregate severity comparison table."""
    st.markdown("**Aggregate Severity Breakdown**")

    sev_colors = {
        "CRITICAL": "#dc3545",
        "HIGH": "#fd7e14",
        "MEDIUM": "#ffc107",
        "LOW": "#28a745"
    }

    # Header row
    cols = st.columns([2, 2, 2, 2])
    cols[0].markdown("**Severity**")
    cols[1].markdown("**Chainguard**")
    cols[2].markdown("**DHI**")
    cols[3].markdown("**Difference**")

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        cg_count = macro.cg_by_severity.get(sev, 0)
        dhi_count = macro.dhi_by_severity.get(sev, 0)
        diff = dhi_count - cg_count
        color = sev_colors.get(sev, "#6c757d")

        cols = st.columns([2, 2, 2, 2])
        cols[0].markdown(f"<span style='color: {color};'>{sev}</span>", unsafe_allow_html=True)
        cols[1].markdown(f"{cg_count}")
        cols[2].markdown(f"{dhi_count}")
        if diff > 0:
            cols[3].markdown(f"<span style='color: #28a745;'>CG better by {diff}</span>", unsafe_allow_html=True)
        elif diff < 0:
            cols[3].markdown(f"<span style='color: #dc3545;'>DHI better by {-diff}</span>", unsafe_allow_html=True)
        else:
            cols[3].markdown("Equal")

    # Total row
    cols = st.columns([2, 2, 2, 2])
    cols[0].markdown("**TOTAL**")
    cols[1].markdown(f"**{macro.cg_total_vulns}**")
    cols[2].markdown(f"**{macro.dhi_total_vulns}**")
    diff = macro.dhi_total_vulns - macro.cg_total_vulns
    if diff > 0:
        cols[3].markdown(f"<span style='color: #28a745;'>**CG better by {diff}**</span>", unsafe_allow_html=True)
    elif diff < 0:
        cols[3].markdown(f"<span style='color: #dc3545;'>**DHI better by {-diff}**</span>", unsafe_allow_html=True)
    else:
        cols[3].markdown("**Equal**")


def render_macro_scoreboard(macro: MacroComparisonResult):
    """Render win/loss scoreboard visualization."""
    st.markdown("**Win/Loss Scoreboard**")

    col1, col2, col3 = st.columns(3)

    with col1:
        pct = f"{macro.cg_wins/macro.total_images*100:.0f}%" if macro.total_images > 0 else "0%"
        st.metric(label="Chainguard Wins", value=macro.cg_wins, delta=pct)

    with col2:
        pct = f"{macro.dhi_wins/macro.total_images*100:.0f}%" if macro.total_images > 0 else "0%"
        st.metric(label="DHI Wins", value=macro.dhi_wins, delta=pct)

    with col3:
        pct = f"{macro.ties/macro.total_images*100:.0f}%" if macro.total_images > 0 else "0%"
        st.metric(label="Ties", value=macro.ties, delta=pct)

    # Visual bar showing proportion
    if macro.total_images > 0:
        cg_pct = macro.cg_wins / macro.total_images * 100
        dhi_pct = macro.dhi_wins / macro.total_images * 100
        tie_pct = macro.ties / macro.total_images * 100

        st.markdown(f"""
        <div style="display: flex; height: 24px; border-radius: 4px; overflow: hidden; margin: 1rem 0;">
            <div style="width: {cg_pct}%; background-color: #28a745;" title="Chainguard {cg_pct:.0f}%"></div>
            <div style="width: {tie_pct}%; background-color: #ffc107;" title="Ties {tie_pct:.0f}%"></div>
            <div style="width: {dhi_pct}%; background-color: #007bff;" title="DHI {dhi_pct:.0f}%"></div>
        </div>
        <div style="display: flex; justify-content: space-between; font-size: 0.8em; color: #666;">
            <span>Chainguard ({cg_pct:.0f}%)</span>
            <span>Ties ({tie_pct:.0f}%)</span>
            <span>DHI ({dhi_pct:.0f}%)</span>
        </div>
        """, unsafe_allow_html=True)


def render_per_image_table(macro: MacroComparisonResult):
    """Render expandable per-image breakdown."""
    with st.expander("Per-Image Details", expanded=False):
        # Sort by total vulnerability difference (CG advantage first)
        sorted_results = sorted(
            macro.results,
            key=lambda r: (r.dhi_result.total_vulns - r.cg_result.total_vulns),
            reverse=True
        )

        # Header
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
                winner_icon = "CG"
                winner_color = "#28a745"
            elif diff < 0:
                winner_icon = "DHI"
                winner_color = "#007bff"
            else:
                winner_icon = "="
                winner_color = "#ffc107"

            cols = st.columns([3, 2, 2, 1])
            cols[0].markdown(f"**{result.image_name}**")
            cols[1].markdown(f"{cg.critical}C/{cg.high}H/{cg.medium}M/{cg.low}L")
            cols[2].markdown(f"{dhi.critical}C/{dhi.high}H/{dhi.medium}M/{dhi.low}L")
            cols[3].markdown(f"<span style='color: {winner_color}; font-weight: bold;'>{winner_icon}</span>", unsafe_allow_html=True)


def render_macro_exports(macro: MacroComparisonResult):
    """Render export buttons for macro comparison."""
    st.markdown("**Export**")

    col_csv, col_json = st.columns(2)

    with col_csv:
        csv_data = export_macro_comparison_csv(macro)
        st.download_button(
            "Export CSV",
            data=csv_data,
            file_name=f"vulncompare_macro_{macro.total_images}images_{datetime.now().strftime('%Y%m%d')}.csv",
            mime="text/csv",
            use_container_width=True
        )

    with col_json:
        json_data = export_macro_comparison_json(macro)
        st.download_button(
            "Export JSON",
            data=json_data,
            file_name=f"vulncompare_macro_{macro.total_images}images_{datetime.now().strftime('%Y%m%d')}.json",
            mime="application/json",
            use_container_width=True
        )


def main():
    """Main application entry point."""
    render_header()

    deployed = is_deployed_mode()

    # Check critical requirements (local mode only)
    if not deployed:
        docker_running = check_docker_running()
        if not docker_running:
            st.error("Docker is not running. Start Docker first: `colima start`")
            return

    # Main flow - check for macro mode first
    if deployed and st.session_state.macro_mode:
        if st.session_state.macro_result is not None:
            render_macro_results()
        else:
            render_macro_image_selector()
    elif st.session_state.comparison_running and not deployed:
        render_comparison_progress()
    elif st.session_state.comparison_result is not None:
        render_results()
    else:
        render_image_selector()

    # Footer
    st.divider()
    render_status_footer()


if __name__ == "__main__":
    main()
