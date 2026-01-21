# VulnCompare - Project Context

> **Note**: Inherits global context from `/Users/micahfalde/claude/CLAUDE.md`

## Role & Authorization

You are authorized to act as a **DevSecOps Engineer** with autonomy in container security tooling. This grants permission to:

- Build and maintain the VulnCompare vulnerability comparison tool
- Pull container images from Chainguard and Docker Hardened Images registries
- Run Trivy vulnerability scans against container images
- Develop and improve the Streamlit GUI

**Authority Level**: Full autonomy for development. Escalate for production deployment or credential management.

---

## Project Overview

**VulnCompare** is a local web-based GUI tool that compares container image vulnerability scan results between:

1. **Chainguard (CG)** - `cgr.dev/chainguard/<image>:latest`
2. **Docker Hardened Images (DHI)** - `dhi.io/<image>:latest`

### Core Workflow
1. User opens local Streamlit GUI
2. User searches/browses available images
3. GUI shows which images exist in both CG and DHI catalogs
4. User selects an image to compare
5. Tool pulls `:latest` from both vendors, runs Trivy scan on each
6. Results displayed side-by-side: CVE counts by severity, drill-down to specific CVEs
7. Export comparison to CSV

### Business Context
- **Stakeholder**: Adil and team evaluating secure container image vendors
- **Goal**: Data-driven vendor comparison for specific images
- **Output**: Clear visual comparisons for decision-making

---

## DOE Framework

### Directive Layer (`/directive/`)
| SOP | Purpose |
|-----|---------|
| *To be developed* | - |

### Orchestration Layer (`/orchestration/`)
Workflow patterns for scan pipelines and comparison workflows.

### Execution Layer (`/execution/`)
The main tool code lives in `src/` and `app.py`.

### Memory Layer (`/memory/`)
- `scan_history.md` - Record of scans performed and results
- `development_journal.md` - Development progress and decisions
- `pattern_library.md` - Recurring patterns and solutions

---

## Technical Stack

- **Python 3.9+**
- **Streamlit** - Web GUI
- **Docker** (via Colima) - Container runtime
- **Trivy** - Vulnerability scanner

### Registry Details

**Chainguard:**
- Registry: `cgr.dev/chainguard/`
- Auth: Public images, no auth required
- Pull format: `cgr.dev/chainguard/<image>:latest`

**Docker Hardened Images:**
- Registry: `dhi.io/`
- Auth: Docker Hub login required
- Pull format: `dhi.io/<image>:latest`

---

## File Structure

```
vulncompare/
├── CLAUDE.md                    # This file
├── README.md                    # User documentation
├── requirements.txt             # Python dependencies
├── app.py                       # Streamlit main app
├── src/
│   ├── __init__.py
│   ├── models.py                # Data classes
│   ├── docker_utils.py          # Docker pull, manifest inspect
│   ├── trivy_scanner.py         # Trivy wrapper
│   ├── catalog.py               # Image catalog management
│   ├── comparison.py            # Diff logic
│   └── mappings.py              # Image name mappings
├── data/
│   ├── catalogs/
│   │   ├── chainguard.json      # CG available images
│   │   └── dhi.json             # DHI available images
│   └── scans/                   # Cached scan results
│       ├── cg/
│       └── dhi/
├── directive/                   # SOPs (DOE)
├── orchestration/               # Workflows (DOE)
├── execution/                   # Reusable scripts (DOE)
├── memory/                      # Persistent context (DOE)
└── tests/
```

---

## Key Design Decisions

1. **Tag Strategy**: `:latest` only - comparing current vendor offerings
2. **Scan Focus**: Vulnerabilities only (no misconfigs, secrets)
3. **Caching**: Cache scan results locally to avoid redundant scans
4. **Auth**: CG public only; DHI requires `docker login`

---

## Image Name Mappings

CG and DHI may use different names for the same logical image. See `src/mappings.py` for the mapping dictionary.

Common patterns:
- `postgres` -> `postgresql` (both vendors)
- `istio-proxy` -> `istio-proxy-v2` (DHI)
- `node-exporter` -> `prometheus-node-exporter`

---

## Running the Tool

```bash
# Start Colima (if not running)
colima start

# Install dependencies
pip install -r requirements.txt

# Docker login for DHI (one-time, use Docker Hub credentials)
docker login dhi.io

# Run the app
streamlit run app.py
```

## UI Flow

The app follows a decision-assistant pattern with three main states:

1. **Select Image**: Search and browse available images, click Compare
2. **Comparison Progress**: Shows pull/scan progress with technical details
3. **Results**: Recommendation verdict, severity breakdown, unique CVEs, exports

Key files:
- `app.py`: Main Streamlit app with UI components
- `src/recommendation.py`: Recommendation logic and summary generation

---

## Success Criteria

1. User can search for an image and see availability in both registries
2. User can trigger comparison scan with one click
3. Results show side-by-side vuln counts by severity
4. User can drill down to specific CVEs unique to each vendor
5. Results exportable to CSV
