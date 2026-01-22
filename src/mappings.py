"""Image name mappings between Chainguard and Docker Hardened Images."""

from typing import Dict, List, Optional, Tuple

# Maps canonical name to (cg_name, dhi_name)
# If None, the image is not available in that registry
IMAGE_MAPPINGS: Dict[str, Tuple[Optional[str], Optional[str]]] = {
    # Databases
    "redis": ("redis", "redis"),
    "postgres": ("postgres", "postgres"),
    "postgresql": ("postgres", "postgres"),
    "mongodb": ("mongodb", "mongodb"),
    "mongo": ("mongodb", "mongodb"),
    "mysql": ("mysql", "mysql"),
    "clickhouse": ("clickhouse", "clickhouse"),
    "elasticsearch": ("elasticsearch", "elasticsearch"),
    "opensearch": ("opensearch", "opensearch"),
    "memcached": ("memcached", "memcached"),
    "valkey": ("valkey", "valkey"),
    "influxdb": ("influxdb", "influxdb"),
    "etcd": ("etcd", "etcd"),
    "zookeeper": ("zookeeper", "zookeeper"),

    # Languages / Runtimes
    "node": ("node", "node"),
    "dotnet-sdk": ("dotnet-sdk", "dotnet"),
    "dotnet": ("dotnet-sdk", "dotnet"),
    "aspnet-runtime": ("aspnet-runtime", "aspnetcore"),
    "aspnetcore": ("aspnet-runtime", "aspnetcore"),
    "python": ("python", "python"),
    "go": ("go", "go"),
    "rust": ("rust", "rust"),
    "ruby": ("ruby", "ruby"),
    "php": ("php", "php"),
    "jdk": ("jdk", "eclipse-temurin"),

    # Networking
    "nginx": ("nginx", "nginx"),
    "haproxy": ("haproxy", "haproxy"),
    "traefik": ("traefik", "traefik"),
    "envoy": ("envoy", "envoy"),
    "caddy": ("caddy", "caddy"),
    "coredns": ("coredns", "coredns"),
    "external-dns": ("external-dns", "external-dns"),

    # Istio
    "istio-proxy": ("istio-proxy", "istio-proxy-v2"),
    "istio-pilot": ("istio-pilot", "istio-pilot"),
    "istio-install-cni": ("istio-install-cni", "istio-install-cni"),

    # Monitoring - Prometheus
    "prometheus": ("prometheus", "prometheus"),
    "prometheus-alertmanager": ("prometheus-alertmanager", "prometheus-alertmanager"),
    "alertmanager": ("prometheus-alertmanager", "prometheus-alertmanager"),
    "prometheus-node-exporter": ("prometheus-node-exporter", "prometheus-node-exporter"),
    "node-exporter": ("prometheus-node-exporter", "prometheus-node-exporter"),
    "prometheus-config-reloader": ("prometheus-config-reloader", "prometheus-config-reloader"),
    "prometheus-operator": ("prometheus-operator", "prometheus-operator"),
    "prometheus-pushgateway": ("prometheus-pushgateway", "prometheus-pushgateway"),

    # Monitoring - Grafana
    "grafana": ("grafana", "grafana"),
    "grafana-alloy": ("grafana-alloy", "grafana-alloy"),
    "grafana-agent": ("grafana-agent", "grafana-agent"),
    "grafana-loki": ("loki", "grafana-loki"),
    "loki": ("loki", "grafana-loki"),
    "grafana-tempo": ("tempo", "grafana-tempo"),
    "tempo": ("tempo", "grafana-tempo"),

    # Monitoring - Logging
    "fluent-bit": ("fluent-bit", "fluent-bit"),
    "fluentd": ("fluentd", "fluentd"),
    "vector": ("vector", "vector"),

    # Monitoring - OpenTelemetry
    "opentelemetry-collector": ("opentelemetry-collector", "opentelemetry-collector"),
    "opentelemetry-operator": ("opentelemetry-operator", "opentelemetry-operator"),

    # Monitoring - Metrics
    "kube-state-metrics": ("kube-state-metrics", "kube-state-metrics"),
    "metrics-server": ("metrics-server", "metrics-server"),
    "thanos": ("thanos", "thanos"),

    # Security - cert-manager
    "cert-manager-controller": ("cert-manager-controller", "cert-manager-controller"),
    "cert-manager-cainjector": ("cert-manager-cainjector", "cert-manager-cainjector"),
    "cert-manager-webhook": ("cert-manager-webhook", "cert-manager-webhook"),
    "cert-manager-acmesolver": ("cert-manager-acmesolver", "cert-manager-acmesolver"),
    "cert-manager-startupapicheck": ("cert-manager-startupapicheck", "cert-manager-startupapicheck"),

    # Security - Vault
    "vault": ("vault", "vault"),
    "vault-k8s": ("vault-k8s", "vault-k8s"),

    # Security - Other
    "kube-rbac-proxy": ("kube-rbac-proxy", "kube-rbac-proxy"),
    "oauth2-proxy": ("oauth2-proxy", "oauth2-proxy"),
    "trivy": ("trivy", "trivy"),
    "cosign": ("cosign", "cosign"),

    # CI/CD
    "velero": ("velero", "velero"),
    "argo-cd": ("argocd", "argo-cd"),
    "argocd": ("argocd", "argo-cd"),
    "jenkins": ("jenkins", "jenkins"),

    # Utilities
    "configmap-reload": ("configmap-reload", "configmap-reload"),
    "reloader": ("reloader", "reloader"),
    "busybox": ("busybox", "busybox"),
    "curl": ("curl", "curl"),
    "kubectl": ("kubectl", "kubectl"),
    "helm": ("helm", "helm"),

    # Other
    "uptime-kuma": ("uptime-kuma", "uptime-kuma"),
    "keycloak": ("keycloak", "keycloak"),
    "dex": ("dex", "dex"),
}

# DHI uses version tags, not 'latest'. Map canonical names to DHI tags.
# Format: canonical_name -> dhi_tag (CG uses 'latest' for all)
# Note: DHI tags often include distro suffix like "-debian13-dev" or "-alpine"
DHI_TAGS: Dict[str, str] = {
    # Databases
    "redis": "8-debian13-dev",
    "postgres": "18-alpine3.22-dev",
    "postgresql": "18-alpine3.22-dev",
    "mongodb": "8.2-debian13-dev",
    "mongo": "8.2-debian13-dev",
    "mysql": "8",
    "clickhouse": "24",
    "elasticsearch": "8",
    "opensearch": "2",
    "memcached": "1",
    "valkey": "8",
    "influxdb": "2",
    "etcd": "3",
    "zookeeper": "3",
    # Languages / Runtimes
    "node": "25-debian13-sfw-ent-dev",
    "dotnet-sdk": "10-sdk",
    "dotnet": "10-sdk",
    "aspnet-runtime": "10",
    "aspnetcore": "10",
    "python": "3",
    "go": "1",
    "rust": "1",
    "ruby": "3",
    "php": "8",
    "jdk": "21",
    # Networking
    "nginx": "1",
    "haproxy": "3-debian13-dev",
    "traefik": "3",
    "envoy": "1",
    "caddy": "2",
    "coredns": "1",
    "external-dns": "0",
    # Istio
    "istio-proxy": "1",
    "istio-pilot": "1",
    "istio-install-cni": "1",
    # Prometheus
    "prometheus": "3",
    "prometheus-alertmanager": "0",
    "alertmanager": "0",
    "prometheus-node-exporter": "1",
    "node-exporter": "1",
    "prometheus-config-reloader": "0",
    "prometheus-operator": "0",
    "prometheus-pushgateway": "1",
    # Grafana
    "grafana": "11",
    "grafana-alloy": "1",
    "grafana-agent": "0",
    "grafana-loki": "3",
    "loki": "3",
    "grafana-tempo": "2",
    "tempo": "2",
    # Logging
    "fluent-bit": "3",
    "fluentd": "1",
    "vector": "0",
    # OpenTelemetry
    "opentelemetry-collector": "0",
    "opentelemetry-operator": "0",
    # Metrics
    "kube-state-metrics": "2",
    "metrics-server": "0",
    "thanos": "0",
    # cert-manager
    "cert-manager-controller": "1",
    "cert-manager-cainjector": "1",
    "cert-manager-webhook": "1",
    "cert-manager-acmesolver": "1",
    "cert-manager-startupapicheck": "1",
    # Vault
    "vault": "1",
    "vault-k8s": "1",
    # Security
    "kube-rbac-proxy": "0",
    "oauth2-proxy": "7",
    "trivy": "0",
    "cosign": "2",
    # CI/CD
    "velero": "1",
    "argo-cd": "2",
    "argocd": "2",
    "jenkins": "2",
    # Utilities
    "configmap-reload": "0",
    "reloader": "1",
    "busybox": "1",
    "curl": "8",
    "kubectl": "1",
    "helm": "3",
    # Other
    "uptime-kuma": "1",
    "keycloak": "26",
    "dex": "2",
}


# Categories for organizing images in the UI
IMAGE_CATEGORIES: Dict[str, List[str]] = {
    "database": [
        "redis", "postgres", "postgresql", "mongodb", "mongo", "mysql",
        "clickhouse", "elasticsearch", "opensearch", "memcached", "valkey",
        "influxdb", "etcd", "zookeeper"
    ],
    "language": [
        "node", "dotnet-sdk", "dotnet", "aspnet-runtime", "aspnetcore",
        "python", "go", "rust", "ruby", "php", "jdk"
    ],
    "networking": [
        "nginx", "haproxy", "traefik", "envoy", "caddy", "coredns",
        "external-dns", "istio-proxy", "istio-pilot", "istio-install-cni"
    ],
    "monitoring": [
        "prometheus", "prometheus-alertmanager", "alertmanager",
        "prometheus-node-exporter", "node-exporter", "prometheus-config-reloader",
        "prometheus-operator", "prometheus-pushgateway", "grafana", "grafana-alloy",
        "grafana-agent", "grafana-loki", "loki", "grafana-tempo", "tempo",
        "fluent-bit", "fluentd", "vector", "opentelemetry-collector",
        "opentelemetry-operator", "kube-state-metrics", "metrics-server", "thanos"
    ],
    "security": [
        "cert-manager-controller", "cert-manager-cainjector", "cert-manager-webhook",
        "cert-manager-acmesolver", "cert-manager-startupapicheck", "vault",
        "vault-k8s", "kube-rbac-proxy", "oauth2-proxy", "trivy", "cosign"
    ],
    "cicd": [
        "velero", "argo-cd", "argocd", "jenkins"
    ],
    "utility": [
        "configmap-reload", "reloader", "busybox", "curl", "kubectl", "helm"
    ],
    "other": [
        "uptime-kuma", "keycloak", "dex"
    ]
}


def get_category(image_name: str) -> str:
    """Get the category for an image."""
    for category, images in IMAGE_CATEGORIES.items():
        if image_name in images:
            return category
    return "other"


def get_cg_image_name(canonical_name: str) -> Optional[str]:
    """Get the Chainguard image name for a canonical name."""
    if canonical_name in IMAGE_MAPPINGS:
        return IMAGE_MAPPINGS[canonical_name][0]
    # Fallback: try exact match
    return canonical_name


def get_dhi_image_name(canonical_name: str) -> Optional[str]:
    """Get the DHI image name for a canonical name."""
    if canonical_name in IMAGE_MAPPINGS:
        return IMAGE_MAPPINGS[canonical_name][1]
    # Fallback: try exact match
    return canonical_name


def get_cg_full_image(canonical_name: str, tag: str = "latest") -> Optional[str]:
    """Get the full Chainguard image reference."""
    name = get_cg_image_name(canonical_name)
    if name:
        return f"cgr.dev/chainguard/{name}:{tag}"
    return None


def get_dhi_full_image(canonical_name: str, tag: Optional[str] = None) -> Optional[str]:
    """Get the full DHI image reference. Uses version tag from DHI_TAGS if not specified."""
    name = get_dhi_image_name(canonical_name)
    if name:
        # DHI doesn't use 'latest' - use version tag from mapping
        if tag is None:
            tag = DHI_TAGS.get(canonical_name, "1")  # Default to "1" if not mapped
        return f"dhi.io/{name}:{tag}"
    return None


def get_all_canonical_names() -> List[str]:
    """Get all unique canonical image names."""
    return sorted(set(IMAGE_MAPPINGS.keys()))
