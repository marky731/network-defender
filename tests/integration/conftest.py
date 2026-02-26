"""Integration test fixtures (requires Docker lab)."""
import pytest
import subprocess
import time


def is_docker_lab_running() -> bool:
    """Check if the Docker lab is running."""
    try:
        result = subprocess.run(
            ["docker", "compose", "ps", "--status", "running", "-q"],
            capture_output=True, text=True, cwd="lab/",
            timeout=5,
        )
        return bool(result.stdout.strip())
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
        return False


@pytest.fixture(scope="session")
def docker_lab():
    """Ensure Docker lab is running for integration tests."""
    if not is_docker_lab_running():
        pytest.skip("Docker lab is not running. Start with: cd lab && docker compose up -d")
    yield
    # Don't tear down - let user manage lab lifecycle
