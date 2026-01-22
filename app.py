"""VulnCompare: Compare vulnerability scans between Chainguard and Docker Hardened Images."""

import streamlit as st
from datetime import datetime, timezone
from typing import List, Optional

from src.models import ComparisonResult, ImageEntry, Vulnerability
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


def add_log(msg: str):
    """Add a log message."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    st.session_state.comparison_logs.append(f"[{timestamp}] {msg}")


def clear_logs():
    """Clear log messages."""
    st.session_state.comparison_logs = []


def render_header():
    """Render the minimal top header."""
    st.title("VulnCompare")
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
    deployed = is_deployed_mode()
    if not deployed:
        with st.expander("Settings", expanded=False):
            render_auth_settings()
    else:
        st.info("Viewing cached scan results. Live scanning requires local setup.")


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

    # Main flow
    if st.session_state.comparison_running and not deployed:
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
