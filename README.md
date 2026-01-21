# VulnCompare

A local web-based GUI tool for comparing container image vulnerability scan results between **Chainguard** and **Docker Hardened Images (DHI)**.

## Purpose

Compare vulnerability posture between two hardened container image vendors to make data-driven decisions about which vendor to use for specific images.

## Features

- Clean, single-column decision-assistant UI
- Search and browse available images
- Automatic recommendation based on vulnerability severity
- Side-by-side comparison of CVE counts by severity
- Unique CVE lists for each vendor
- Export to CSV, JSON, or copy summary to clipboard
- Technical details hidden by default (available in expanders)

## Prerequisites

- **Docker** (via Colima or Docker Desktop)
- **Trivy** vulnerability scanner
- **Python 3.9+**

## Installation

```bash
# Install Colima and Docker CLI (if not installed)
brew install colima docker

# Start Colima
colima start

# Install Trivy
brew install trivy

# Install Python dependencies
pip install -r requirements.txt

# Login to DHI registry (use Docker Hub credentials)
docker login dhi.io
```

## Usage

```bash
# Start the app
streamlit run app.py
```

The app will open in your browser at `http://localhost:8501`.

### Workflow

1. **Select Image**: Search for an image or browse the catalog
2. **Compare**: Click "Compare" on any image available in both registries
3. **Review Results**: See recommendation, severity breakdown, and unique CVEs
4. **Export**: Download CSV, JSON, or copy summary text

## Project Structure

```
vulncompare/
├── app.py                  # Streamlit main app
├── src/
│   ├── models.py           # Data classes
│   ├── mappings.py         # Image name mappings
│   ├── docker_utils.py     # Docker utilities
│   ├── trivy_scanner.py    # Trivy wrapper
│   ├── catalog.py          # Image catalog management
│   └── comparison.py       # Comparison logic
├── data/
│   ├── catalogs/           # Cached availability data
│   └── scans/              # Cached Trivy scan results
└── memory/                 # Development context (DOE framework)
```

## Registries

- **Chainguard**: `cgr.dev/chainguard/<image>:latest` (public, no auth)
- **DHI**: `dhi.io/<image>:latest` (requires Docker Hub login)

## Adding New Images

Edit `src/mappings.py` to add new image mappings:

```python
IMAGE_MAPPINGS = {
    "canonical-name": ("cg-name", "dhi-name"),
    # ...
}
```

## License

Internal tool - not for distribution.
