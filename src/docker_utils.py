"""Docker utilities for pulling images and checking availability."""

import json
import subprocess
from typing import List, Optional, Tuple


def run_command(cmd: List[str], timeout: int = 300) -> Tuple[int, str, str]:
    """Run a shell command and return (return_code, stdout, stderr)."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", "Command timed out"
    except Exception as e:
        return -1, "", str(e)


def check_docker_running() -> bool:
    """Check if Docker daemon is running."""
    code, _, _ = run_command(["docker", "info"], timeout=10)
    return code == 0


def check_image_exists(image: str) -> bool:
    """Check if an image exists in the registry using docker manifest inspect."""
    code, _, _ = run_command(["docker", "manifest", "inspect", image], timeout=30)
    return code == 0


def pull_image(image: str, progress_callback=None) -> tuple[bool, str]:
    """
    Pull a Docker image.

    Returns (success, message).
    """
    if progress_callback:
        progress_callback(f"Pulling {image}...")

    code, stdout, stderr = run_command(["docker", "pull", image], timeout=600)

    if code == 0:
        return True, f"Successfully pulled {image}"
    else:
        error_msg = stderr or stdout or "Unknown error"
        return False, f"Failed to pull {image}: {error_msg}"


def get_image_digest(image: str) -> Optional[str]:
    """Get the digest of a pulled image."""
    code, stdout, stderr = run_command(
        ["docker", "inspect", "--format={{.RepoDigests}}", image],
        timeout=30
    )
    if code == 0 and stdout.strip():
        # Output format: [registry/image@sha256:...]
        digests = stdout.strip().strip("[]").split()
        if digests:
            return digests[0]
    return None


def image_pulled_locally(image: str) -> bool:
    """Check if an image is already pulled locally."""
    code, _, _ = run_command(["docker", "image", "inspect", image], timeout=10)
    return code == 0


def remove_image(image: str) -> bool:
    """Remove a local image."""
    code, _, _ = run_command(["docker", "rmi", image], timeout=30)
    return code == 0


def docker_login(registry: str, username: str, password: str) -> Tuple[bool, str]:
    """
    Login to a Docker registry.

    Returns (success, message).
    """
    try:
        # Use stdin to pass password securely
        result = subprocess.run(
            ["docker", "login", registry, "-u", username, "--password-stdin"],
            input=password,
            capture_output=True,
            text=True,
            timeout=30
        )
        if result.returncode == 0:
            return True, "Login successful"
        else:
            error = result.stderr or result.stdout or "Unknown error"
            return False, error.strip()
    except subprocess.TimeoutExpired:
        return False, "Login timed out"
    except Exception as e:
        return False, str(e)


def get_docker_login_status() -> dict:
    """Check Docker login status for registries."""
    status = {
        "dhi.io": False,
        "cgr.dev": True,  # Public, no auth needed
    }

    # Check DHI login by looking at config
    try:
        import os
        config_path = os.path.expanduser("~/.docker/config.json")
        if os.path.exists(config_path):
            with open(config_path) as f:
                config = json.load(f)
                auths = config.get("auths", {})
                # DHI registry
                if "dhi.io" in auths or "https://dhi.io" in auths:
                    status["dhi.io"] = True
    except Exception:
        pass

    return status
