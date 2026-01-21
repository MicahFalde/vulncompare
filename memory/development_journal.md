# Development Journal

Chronological record of development work, decisions, and learnings.

---

## 2026-01-21 - Initial Project Setup

**Context**: Building VulnCompare tool per specification from Claude UI ideation session.

**Work Done**:
- Installed Docker (via Colima) and Trivy
- Created project structure following DOE framework
- Implemented core modules:
  - `models.py` - Data classes for vulnerabilities, scan results, comparisons
  - `mappings.py` - Image name mappings between CG and DHI
  - `docker_utils.py` - Docker pull, manifest inspect utilities
  - `trivy_scanner.py` - Trivy wrapper with caching
  - `catalog.py` - Image catalog management
  - `comparison.py` - Comparison logic and CSV export
  - `app.py` - Streamlit GUI

**Decisions Made**:
- Used Colima instead of Docker Desktop (avoids sudo issues and licensing)
- DHI registry confirmed as `docker.io/dhi/<image>:latest`
- Implemented scan caching to avoid redundant Trivy runs

**Learnings**:
- Colima is a lightweight alternative to Docker Desktop that works well on macOS

**Next Steps**:
- Test with real images (redis, nginx, postgres)
- Verify DHI registry path
- Add more images to the mapping as discovered
