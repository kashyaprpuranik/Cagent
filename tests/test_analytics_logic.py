import pytest
from unittest.mock import MagicMock, patch
import json
from datetime import datetime, timezone, timedelta

# Import the module under test
from services.warden.routers import analytics

@pytest.fixture
def mock_docker_client():
    with patch("services.warden.routers.analytics.docker_client") as mock:
        yield mock

@pytest.fixture
def sample_logs():
    now = datetime.now(timezone.utc)
    logs = []
    # Blocked entry
    logs.append(json.dumps({
        "timestamp": now.isoformat(),
        "response_code": 403,
        "authority": "blocked.com",
        "bytes_sent": 100,
        "bytes_received": 50,
        "duration_ms": 10
    }))
    # Allowed entry
    logs.append(json.dumps({
        "timestamp": (now - timedelta(minutes=10)).isoformat(),
        "response_code": 200,
        "authority": "allowed.com",
        "bytes_sent": 200,
        "bytes_received": 100,
        "duration_ms": 20
    }))
    # Another blocked entry
    logs.append(json.dumps({
        "timestamp": (now - timedelta(minutes=5)).isoformat(),
        "response_code": 403,
        "authority": "blocked.com",
        "bytes_sent": 100,
        "bytes_received": 50,
        "duration_ms": 15
    }))
    return "\n".join(logs)

def test_get_blocked_domains(mock_docker_client, sample_logs):
    # Setup mock
    mock_container = MagicMock()
    mock_container.logs.return_value = sample_logs.encode("utf-8")
    mock_docker_client.containers.get.return_value = mock_container

    # Call function
    result = analytics.get_blocked_domains(hours=1, limit=10)

    # Verify
    assert "blocked_domains" in result
    domains = result["blocked_domains"]
    assert len(domains) == 1
    assert domains[0]["domain"] == "blocked.com"
    assert domains[0]["count"] == 2

def test_get_blocked_timeseries(mock_docker_client, sample_logs):
    # Setup mock
    mock_container = MagicMock()
    mock_container.logs.return_value = sample_logs.encode("utf-8")
    mock_docker_client.containers.get.return_value = mock_container

    # Call function
    result = analytics.get_blocked_timeseries(hours=1, buckets=2)

    # Verify
    assert "buckets" in result
    buckets = result["buckets"]
    assert len(buckets) == 2
    # Verify we have counts (exact bucket distribution depends on time but we know total is 2)
    total_count = sum(b["count"] for b in buckets)
    assert total_count == 2

def test_get_bandwidth(mock_docker_client, sample_logs):
    # Setup mock
    mock_container = MagicMock()
    mock_container.logs.return_value = sample_logs.encode("utf-8")
    mock_docker_client.containers.get.return_value = mock_container

    # Call function
    result = analytics.get_bandwidth(hours=1, limit=10)

    # Verify
    assert "domains" in result
    domains = result["domains"]
    assert len(domains) == 2 # blocked.com and allowed.com

    blocked = next(d for d in domains if d["domain"] == "blocked.com")
    assert blocked["bytes_sent"] == 200
    assert blocked["bytes_received"] == 100

    allowed = next(d for d in domains if d["domain"] == "allowed.com")
    assert allowed["bytes_sent"] == 200
    assert allowed["bytes_received"] == 100

@patch("services.warden.routers.analytics.subprocess.run")
@patch("services.warden.routers.analytics.Path") # Mock Path to avoid reading real file
def test_diagnose_domain(mock_path, mock_subprocess, mock_docker_client, sample_logs):
    # Setup logs mock
    mock_container = MagicMock()
    mock_container.logs.return_value = sample_logs.encode("utf-8")
    mock_docker_client.containers.get.side_effect = lambda name: mock_container # Returns same mock for both ENVOY and COREDNS lookup if needed, but diagnose uses subprocess for DNS

    # Setup subprocess mock for DNS
    mock_proc = MagicMock()
    mock_proc.returncode = 0
    mock_proc.stdout = "Address: 1.2.3.4"
    mock_subprocess.return_value = mock_proc

    # Setup Path mock
    mock_path_instance = MagicMock()
    mock_path_instance.exists.return_value = True
    mock_path_instance.read_text.return_value = "domains:\n  - domain: allowed.com"
    mock_path.return_value = mock_path_instance

    # Call function
    result = analytics.diagnose_domain(domain="blocked.com")

    # Verify
    assert result["domain"] == "blocked.com"
    assert result["in_allowlist"] == False
    assert result["dns_result"] == "1.2.3.4"
    assert "Proxy returns 403" in result["diagnosis"]
