# Pattern Library

Recurring patterns and solutions discovered during development.

---

## Image Naming Patterns

### Chainguard Naming Conventions
- Generally lowercase, hyphenated
- `postgresql` (not `postgres`)
- `prometheus-node-exporter` (not `node-exporter`)

### DHI Naming Conventions
- Similar to Chainguard but some differences
- `istio-proxy-v2` (vs CG's `istio-proxy`)
- Check catalog for exact names

---

## Common Issues

### Issue: Docker not running
**Solution**: Start Colima with `colima start`

### Issue: DHI pull fails
**Solution**: Ensure logged in with `docker login docker.io`

### Issue: Trivy scan times out
**Solution**: Large images may need more time. Check if image was partially pulled.

---

## Scan Result Patterns

*Patterns will be added as more scans are performed.*
