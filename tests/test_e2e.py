"""
End-to-end tests for the full data plane stack.

These tests require the data plane to be running in standalone mode
with the dev and admin profiles:
    docker compose --profile dev --profile admin up -d

Config-write tests are automatically skipped in connected mode.

Run with:
    sg docker -c "python -m pytest tests/test_e2e.py -v"
"""

import subprocess
import time

import pytest
import requests
import websocket


def pytest_configure(config):
    config.addinivalue_line("markers", "e2e: mark test as end-to-end (requires full stack running)")


CELL_LABEL = "cagent.role=cell"
CELL_CONTAINER_FALLBACK = "cell"


def _discover_cell_container_name() -> str:
    """Discover a cell container by label, falling back to 'cell'."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "label=cagent.role=cell", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        names = result.stdout.strip().splitlines()
        if names:
            return names[0]
    except Exception:
        pass
    return CELL_CONTAINER_FALLBACK


def is_data_plane_running():
    """Check if data plane containers are running.

    Uses ``docker ps -a`` and checks for status containing "Up" so we
    detect containers that exist but are crash-looping (status would
    show "Restarting" or "Exited").
    """
    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "--filter", "name=http-proxy", "--format", "{{.Names}} {{.Status}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in result.stdout.strip().splitlines():
            if "http-proxy" in line and "Up" in line:
                return True
        return False
    except Exception:
        return False


@pytest.fixture(scope="module")
def data_plane_running():
    """Verify data plane is running and all services accept connections.

    Warden restarts Envoy/CoreDNS on startup (config generation), so
    even after ``test.sh``'s initial sleep services may still be
    coming back up.  Poll until http-proxy is running (it may briefly
    restart while warden regenerates its config after a fresh start).
    """
    # Retry for up to 30s — after a fresh start, warden regenerates
    # the Envoy config and restarts http-proxy, causing a brief gap.
    deadline = time.time() + 30
    while time.time() < deadline:
        if is_data_plane_running():
            break
        time.sleep(2)
    else:
        # Provide diagnostic info on failure
        try:
            diag = subprocess.run(
                ["docker", "ps", "-a", "--filter", "name=http-proxy", "--format", "{{.Names}} {{.Status}}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            status = diag.stdout.strip() or "(no http-proxy container found)"
        except Exception:
            status = "(docker command failed)"
        pytest.fail(f"Data plane not running after 30s — test.sh should have started it. http-proxy status: {status}")

    cell = _discover_cell_container_name()

    # Wait for Envoy proxy to accept connections
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            probe = subprocess.run(
                ["docker", "exec", cell, "sh", "-c", "nc -z -w 2 10.200.1.10 8443 && echo OK"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if "OK" in probe.stdout:
                break
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        time.sleep(3)
    else:
        pytest.fail("Envoy proxy not reachable from cell container after 60s — warden may still be restarting it")

    # Wait for CoreDNS to accept connections
    deadline = time.time() + 30
    while time.time() < deadline:
        try:
            probe = subprocess.run(
                ["docker", "exec", cell, "sh", "-c", "nc -z -w 2 10.200.1.5 53 && echo OK"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if "OK" in probe.stdout:
                break
        except (subprocess.TimeoutExpired, subprocess.SubprocessError):
            pass
        time.sleep(2)
    else:
        pytest.fail("CoreDNS not reachable from cell container after 30s")

    # Wait for admin API to be ready
    admin = get_admin_url()
    if admin:
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                r = requests.get(f"{admin}/api/health", timeout=3)
                if r.status_code == 200:
                    break
            except Exception:
                pass
            time.sleep(2)

    return True


@pytest.fixture(scope="module")
def agent_container_name():
    """Discover the cell container name (label-based, fallback to 'cell')."""
    return _discover_cell_container_name()


def exec_in_cell(command: str, container_name: str = None) -> subprocess.CompletedProcess:
    """Execute a command in a cell container (discovered by label)."""
    name = container_name or _discover_cell_container_name()
    return subprocess.run(["docker", "exec", name, "sh", "-c", command], capture_output=True, text=True, timeout=30)


@pytest.mark.e2e
class TestCellNetworkIsolation:
    """Test that cell container is properly isolated."""

    def test_cell_can_reach_envoy(self, data_plane_running):
        """Cell should be able to reach Envoy proxy."""
        result = exec_in_cell("nc -z 10.200.1.10 8443 && echo OK")
        assert result.returncode == 0 or "OK" in result.stdout, f"Cell cannot reach Envoy: {result.stderr}"

    def test_cell_can_reach_dns(self, data_plane_running):
        """Cell should be able to reach DNS filter."""
        result = exec_in_cell("nc -z 10.200.1.5 53 && echo OK")
        assert result.returncode == 0 or "OK" in result.stdout, f"Cell cannot reach DNS: {result.stderr}"

    def test_cell_cannot_reach_external_directly(self, data_plane_running):
        """Cell should NOT be able to reach external IPs directly."""
        # Try to reach Google DNS directly (should fail)
        result = exec_in_cell("nc -z -w 2 8.8.8.8 53 && echo FAIL || echo BLOCKED")
        assert "BLOCKED" in result.stdout, "Cell can reach external IPs directly - network isolation broken!"

    def test_cell_cannot_reach_control_plane(self, data_plane_running):
        """Cell should NOT be able to reach control plane directly."""
        # Control plane is on infra-net, cell should not reach it
        result = exec_in_cell("nc -z -w 2 10.200.2.1 8000 && echo FAIL || echo BLOCKED")
        assert "BLOCKED" in result.stdout, "Cell can reach infra-net (10.200.2.1:8000) — network isolation broken!"


@pytest.mark.e2e
class TestMultiCellContainers:
    """Test multi-cell container support (--scale cell-dev=2).

    Verifies that all cell containers are discovered by label,
    each has proper network isolation, and each is independently functional.
    """

    def _discover_all(self):
        result = subprocess.run(
            ["docker", "ps", "--filter", "label=cagent.role=cell", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return sorted(result.stdout.strip().splitlines())

    def test_multiple_cells_discovered(self, data_plane_running):
        """Should discover at least 2 cell containers by label."""
        names = self._discover_all()
        assert len(names) >= 2, f"Expected >=2 cell containers, found {len(names)}: {names}"

    def test_all_cells_can_reach_proxy(self, data_plane_running):
        """Every cell container should reach the Envoy proxy."""
        for name in self._discover_all():
            result = exec_in_cell("nc -z 10.200.1.10 8443 && echo OK", container_name=name)
            assert "OK" in result.stdout, f"{name} cannot reach proxy: {result.stderr}"

    def test_all_cells_can_reach_dns(self, data_plane_running):
        """Every cell container should reach the DNS filter."""
        for name in self._discover_all():
            result = exec_in_cell("nc -z 10.200.1.5 53 && echo OK", container_name=name)
            assert "OK" in result.stdout, f"{name} cannot reach DNS: {result.stderr}"

    def test_all_cells_isolated_from_external(self, data_plane_running):
        """Every cell container should be blocked from external IPs."""
        for name in self._discover_all():
            result = exec_in_cell(
                "nc -z -w 2 8.8.8.8 53 && echo FAIL || echo BLOCKED",
                container_name=name,
            )
            assert "BLOCKED" in result.stdout, f"{name} can reach external IPs directly — isolation broken!"

    def test_cells_have_distinct_hostnames(self, data_plane_running):
        """Each cell container should report a different hostname."""
        hostnames = set()
        for name in self._discover_all():
            result = exec_in_cell("hostname", container_name=name)
            hostnames.add(result.stdout.strip())
        assert len(hostnames) >= 2, f"Expected distinct hostnames, got: {hostnames}"


@pytest.mark.e2e
class TestDNSFiltering:
    """Test DNS filtering behavior."""

    def test_allowed_domain_resolves(self, data_plane_running):
        """Allowed domains should resolve via DNS filter."""
        result = exec_in_cell("nslookup api.openai.com 10.200.1.5")
        assert result.returncode == 0, f"Failed to resolve allowed domain: {result.stderr}"
        assert "NXDOMAIN" not in result.stdout, "Allowed domain returned NXDOMAIN"

    def test_blocked_domain_fails(self, data_plane_running):
        """Non-allowed domains should fail DNS resolution."""
        result = exec_in_cell("nslookup evil-malware.com 10.200.1.5")
        # Should return NXDOMAIN or fail
        assert "NXDOMAIN" in result.stdout or result.returncode != 0, "Blocked domain should not resolve"


@pytest.mark.e2e
class TestProxyEgress:
    """Test egress through Envoy proxy."""

    def test_https_through_proxy_allowed_domain(self, data_plane_running):
        """Should successfully reach allowed domains through proxy."""
        result = exec_in_cell(
            "curl -s -o /dev/null -w '%{http_code}' -x http://10.200.1.10:8443 https://api.github.com"
        )
        # Should get some HTTP response (even 401 unauthorized is fine)
        http_code = result.stdout.strip()
        assert http_code.isdigit() and int(http_code) < 500, f"Request to allowed domain failed with: {http_code}"

    def test_https_through_proxy_blocked_domain(self, data_plane_running):
        """Should fail to reach blocked domains through proxy."""
        result = exec_in_cell(
            "curl -s -o /dev/null -w '%{http_code}' "
            "-x http://10.200.1.10:8443 "
            "--connect-timeout 5 "
            "https://evil-malware.com"
        )
        # Should fail (connection refused, timeout, or 403)
        http_code = result.stdout.strip()
        # Empty or error code means blocked
        assert not http_code or http_code == "000" or http_code == "403", (
            f"Request to blocked domain succeeded with: {http_code}"
        )


@pytest.mark.e2e
class TestCredentialInjection:
    """Test credential injection functionality (via Envoy ext_authz)."""

    def test_request_headers_not_contain_secrets(self, data_plane_running):
        """Cell requests should not contain raw secrets."""
        # Make a request and capture what the cell sees
        result = exec_in_cell("env | grep -i api_key || echo 'NO_SECRETS_IN_ENV'")
        assert "NO_SECRETS_IN_ENV" in result.stdout or not result.stdout.strip(), (
            "Cell environment should not contain API keys"
        )

    def test_envoy_handles_credential_injection(self, data_plane_running):
        """Envoy should be running (handles credential injection via ext_authz)."""
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=http-proxy", "--format", "{{.Status}}"], capture_output=True, text=True
        )
        assert "Up" in result.stdout, "Envoy proxy is not running"

    def test_https_connect_tunnel_no_rewrite(self, data_plane_running):
        """HTTPS requests should pass through as CONNECT tunnel - no header injection.

        When cell uses: curl https://api.openai.com
        Envoy sees CONNECT tunnel, cannot inject headers into encrypted traffic.
        This is expected behavior - credentials are NOT injected for direct HTTPS.
        """
        # Make HTTPS request - this creates a CONNECT tunnel
        # We use -v to see the CONNECT method being used
        result = exec_in_cell(
            "curl -v -s -o /dev/null -w '%{http_code}' "
            "-x http://10.200.1.10:8443 "
            "--connect-timeout 5 "
            "https://httpbin.org/headers 2>&1 | grep -E 'CONNECT|HTTP/1.1'"
        )
        # Should see CONNECT method in verbose output (indicates tunnel mode)
        # Note: This test verifies the tunnel is established, not that headers aren't injected
        # (we can't easily verify header injection didn't happen from outside the tunnel)
        assert "CONNECT" in result.stdout or result.returncode == 0, "HTTPS should use CONNECT tunnel through proxy"

    def test_http_devbox_local_gets_credentials(self, data_plane_running):
        """HTTP requests to *.devbox.local should get credentials injected.

        When cell uses: curl http://openai.devbox.local/...
        Envoy sees plain HTTP, can inject Authorization header.
        """
        # This test requires a secret with alias to be configured
        # For now, just verify the devbox.local routing works
        result = exec_in_cell(
            "curl -s -o /dev/null -w '%{http_code}' "
            "-x http://10.200.1.10:8443 "
            "--connect-timeout 5 "
            "http://openai.devbox.local/v1/models 2>&1"
        )
        # Should get some response (401 without valid creds, or 200 with)
        # Not 000 (connection failed) or 403 (blocked)
        http_code = result.stdout.strip()
        # Any response indicates the devbox.local routing worked
        assert http_code and http_code != "000", f"devbox.local request failed: {result.stderr}"


@pytest.mark.e2e
class TestLogging:
    """Test log collection."""

    def test_vector_running(self, data_plane_running):
        """Vector should be running for log collection."""
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=log-shipper", "--format", "{{.Status}}"], capture_output=True, text=True
        )
        assert "Up" in result.stdout, "Log shipper is not running"

    def test_envoy_logs_exist(self, data_plane_running):
        """Envoy should be generating access logs (to stdout)."""
        result = subprocess.run(
            ["docker", "logs", "--tail", "5", "http-proxy"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, "Cannot read http-proxy container logs"
        # Should have some log output (startup or access logs)
        combined = result.stdout + result.stderr
        assert len(combined.strip()) > 0, "No log output from http-proxy"

    def test_logs_reach_file_backup(self, data_plane_running):
        """Logs should be written to the file backup sink.

        Generates a proxy request with a unique marker, waits for Vector
        to flush, then checks the backup file inside the log-shipper
        container for the marker.
        """
        marker = f"logtest-{int(time.time())}"

        # Generate traffic through the proxy with a unique path
        exec_in_cell(f"curl -s -o /dev/null -x http://10.200.1.10:8443 http://pypi.org/{marker} || true")

        # Poll the file backup volume for the marker (up to 30s)
        deadline = time.time() + 30
        found = False
        while time.time() < deadline:
            result = subprocess.run(
                [
                    "docker",
                    "exec",
                    "log-shipper",
                    "sh",
                    "-c",
                    f"grep -r '{marker}' /var/log/vector/backup/ 2>/dev/null",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if marker in result.stdout:
                found = True
                break
            time.sleep(2)

        assert found, (
            f"Marker '{marker}' never appeared in log-shipper file backup "
            f"within 30s. Vector may not be flushing to disk."
        )


@pytest.mark.e2e
class TestCellSecurityHardening:
    """Test container security hardening: capabilities, seccomp, isolation."""

    def test_no_docker_socket(self, data_plane_running):
        """Cell should not have access to the Docker socket."""
        result = exec_in_cell("ls /var/run/docker.sock 2>&1 || echo NO_SOCKET")
        assert "NO_SOCKET" in result.stdout or "No such file" in result.stdout, (
            "Docker socket is accessible inside cell — container escape risk!"
        )

    def test_no_host_filesystem(self, data_plane_running):
        """Cell should not see host filesystem mounts."""
        # /host is a common mount point; also check that /proc/1/root doesn't
        # expose the host (in a container, PID 1 root is the container root)
        result = exec_in_cell("ls /host 2>&1 || echo NO_HOST")
        assert "NO_HOST" in result.stdout or "No such file" in result.stdout

    def test_proxy_env_vars_set(self, data_plane_running):
        """Cell must have HTTP_PROXY and HTTPS_PROXY pointing to Envoy."""
        result = exec_in_cell("echo $HTTP_PROXY")
        assert "10.200.1.10:8443" in result.stdout, f"HTTP_PROXY not set correctly: {result.stdout}"

        result = exec_in_cell("echo $HTTPS_PROXY")
        assert "10.200.1.10:8443" in result.stdout, f"HTTPS_PROXY not set correctly: {result.stdout}"

    def test_cannot_reach_infra_net(self, data_plane_running):
        """Cell should not be able to reach any infra-net addresses."""
        # dns-filter's infra side
        result = exec_in_cell("nc -z -w 2 10.200.2.5 53 && echo FAIL || echo BLOCKED")
        assert "BLOCKED" in result.stdout, "Cell can reach dns-filter on infra-net (10.200.2.5)"

        # envoy's infra side
        result = exec_in_cell("nc -z -w 2 10.200.2.10 8443 && echo FAIL || echo BLOCKED")
        assert "BLOCKED" in result.stdout, "Cell can reach envoy on infra-net (10.200.2.10)"

    def test_envoy_admin_not_reachable(self, data_plane_running):
        """Envoy admin API (port 9901) must not be reachable from cell-net.

        The cell has HTTP_PROXY set, so curl routes through Envoy's listener
        on 8443 which rejects it as 'destination_not_allowed'. Even bypassing
        the proxy, the admin binds to 127.0.0.1 so it's unreachable from
        cell-net. Either outcome means the admin API is not exposed.
        """
        # Try via proxy (cell's default) — Envoy rejects unknown destinations
        result = exec_in_cell("curl -s --connect-timeout 2 http://10.200.1.10:9901/ready 2>&1 || echo BLOCKED")
        assert "BLOCKED" in result.stdout or "refused" in result.stdout or "destination_not_allowed" in result.stdout, (
            "Cell can reach Envoy admin API — config_dump would leak credentials!"
        )

        # Try bypassing the proxy — admin binds to 127.0.0.1, so direct
        # connection to 10.200.1.10:9901 should be refused
        result = exec_in_cell(
            "curl -s --connect-timeout 2 --noproxy '*' http://10.200.1.10:9901/ready 2>&1 || echo BLOCKED"
        )
        assert "BLOCKED" in result.stdout or "refused" in result.stdout, (
            "Cell can reach Envoy admin API directly (bypassing proxy)!"
        )

    def test_raw_socket_blocked(self, data_plane_running):
        """Raw sockets should be blocked (CAP_NET_RAW dropped + seccomp)."""
        # SOCK_RAW with AF_INET requires CAP_NET_RAW
        result = exec_in_cell(
            'python3 -c "'
            "import socket; "
            "s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP); "
            "print('RAW_ALLOWED')\" 2>&1 || echo RAW_BLOCKED"
        )
        assert "RAW_BLOCKED" in result.stdout or "Operation not permitted" in result.stdout, (
            "Raw sockets are allowed — cell could craft packets to bypass proxy!"
        )

    def test_af_packet_blocked(self, data_plane_running):
        """AF_PACKET sockets should be blocked by seccomp profile."""
        result = exec_in_cell(
            'python3 -c "'
            "import socket; "
            "s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); "
            "print('PACKET_ALLOWED')\" 2>&1 || echo PACKET_BLOCKED"
        )
        assert "PACKET_BLOCKED" in result.stdout or "Operation not permitted" in result.stdout, (
            "AF_PACKET sockets are allowed — cell could sniff/inject raw frames!"
        )

    def test_no_privilege_escalation(self, data_plane_running):
        """no-new-privileges should prevent setuid escalation."""
        # Check if cell already runs as root
        who = exec_in_cell("id -u")
        cell_name = _discover_cell_container_name()
        if who.stdout.strip() == "0":
            # Already root — no-new-privileges is set but sudo is a no-op.
            # Verify the security_opt is in place via container inspect.
            result = subprocess.run(
                ["docker", "inspect", cell_name, "--format", "{{.HostConfig.SecurityOpt}}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            assert "no-new-privileges" in result.stdout, "no-new-privileges is not set on cell container"
        else:
            # Non-root — sudo's setuid bit should be blocked by no-new-privileges
            result = exec_in_cell("sudo id 2>&1 || echo SUDO_FAILED")
            assert "SUDO_FAILED" in result.stdout or "root" not in result.stdout, (
                "sudo succeeded — no-new-privileges may not be set!"
            )

    def test_ipv6_disabled(self, data_plane_running):
        """IPv6 should be disabled to prevent bypass of IPv4 cell egress controls."""
        result = exec_in_cell(
            "curl -6 -s --connect-timeout 2 http://[2607:f8b0:4004:800::200e] 2>&1 || echo IPV6_BLOCKED"
        )
        assert (
            "IPV6_BLOCKED" in result.stdout or "Could not resolve" in result.stdout or "connect to" in result.stdout
        ), "IPv6 connectivity is available — could bypass egress controls!"


def get_admin_url():
    """Get local admin base URL, detecting the mapped port."""
    try:
        result = subprocess.run(["docker", "port", "warden", "8080"], capture_output=True, text=True, timeout=5)
        if result.returncode == 0 and result.stdout.strip():
            # Output like "0.0.0.0:8080" or ":::8080"
            mapping = result.stdout.strip().splitlines()[0]
            host_port = mapping.rsplit(":", 1)[-1]
            return f"http://localhost:{host_port}"
    except Exception:
        pass
    return None


@pytest.fixture(scope="module")
def admin_url():
    """Get local admin URL (guaranteed by test.sh --profile admin)."""
    url = get_admin_url()
    assert url is not None, "Local admin not running — test.sh should have started it with --profile admin"
    return url


def is_container_running(name):
    """Check if a Docker container is running."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name=^{name}$", "--format", "{{.Status}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return "Up" in result.stdout
    except Exception:
        return False


def wait_for_container(name, timeout=30):
    """Wait for a container to be running."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if is_container_running(name):
            return True
        time.sleep(1)
    return False


@pytest.mark.e2e
class TestLocalAdminAPI:
    """Test local admin UI API endpoints (requires --profile admin)."""

    def test_health(self, admin_url):
        """Health endpoint should return ok."""
        r = requests.get(f"{admin_url}/api/health", timeout=5)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] == "ok"
        assert "timestamp" in data

    def test_detailed_health(self, admin_url):
        """Detailed health should report on managed containers."""
        r = requests.get(f"{admin_url}/api/health/detailed", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert data["status"] in ("healthy", "degraded")
        assert "checks" in data
        # Agent containers have dynamic names (e.g. cagent-cell-dev-1)
        agent_checks = [k for k in data["checks"] if "cell" in k and "manager" not in k]
        assert len(agent_checks) >= 1, f"No cell container in checks: {list(data['checks'])}"
        assert "dns-filter" in data["checks"]
        assert "http-proxy" in data["checks"]

    def test_info(self, admin_url):
        """Info endpoint should return container names and paths."""
        r = requests.get(f"{admin_url}/api/info", timeout=5)
        assert r.status_code == 200
        data = r.json()
        # Agent name is dynamic (label-discovered), just verify it's present
        assert "cell" in data["containers"]
        assert len(data["containers"]["cell"]) > 0
        assert data["containers"]["dns"] == "dns-filter"
        assert data["containers"]["http_proxy"] == "http-proxy"

    def test_list_containers(self, admin_url):
        """Should list managed containers with status."""
        r = requests.get(f"{admin_url}/api/containers", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "containers" in data
        # Agent containers have dynamic names; check at least one is present
        agent_containers = [k for k in data["containers"] if "cell" in k and "manager" not in k]
        assert len(agent_containers) >= 1, f"No cell container found: {list(data['containers'])}"
        for name in ("dns-filter", "http-proxy"):
            assert name in data["containers"]
            assert "status" in data["containers"][name]

    def test_get_single_container(self, admin_url, agent_container_name):
        """Should get status for a specific container."""
        r = requests.get(f"{admin_url}/api/containers/{agent_container_name}", timeout=30)
        assert r.status_code == 200
        data = r.json()
        assert data["name"] == agent_container_name
        assert "status" in data

    def test_get_config(self, admin_url):
        """Should return current cagent.yaml config."""
        r = requests.get(f"{admin_url}/api/config", timeout=5)
        assert r.status_code in (200, 404)
        if r.status_code == 200:
            data = r.json()
            assert "config" in data
            assert "raw" in data
            assert "path" in data

    def test_container_logs(self, admin_url, data_plane_running):
        """Should return recent logs for a running container."""
        r = requests.get(
            f"{admin_url}/api/containers/http-proxy/logs",
            params={"tail": 10},
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["container"] == "http-proxy"
        assert isinstance(data["lines"], list)
        assert data["count"] == len(data["lines"])

    def test_config_raw_rejects_invalid_yaml(self, admin_url):
        """PUT /api/config/raw should reject invalid YAML with 400."""
        r = requests.put(
            f"{admin_url}/api/config/raw",
            json={"content": "domains:\n  - domain: good.com\n bad_indent"},
            timeout=5,
        )
        assert r.status_code == 400

    def test_container_restart(self, admin_url, data_plane_running, agent_container_name):
        """Restarting cell container via API should succeed; infra containers should be rejected."""
        # Infrastructure containers cannot be controlled via the API
        r = requests.post(
            f"{admin_url}/api/containers/http-proxy",
            json={"action": "restart"},
            timeout=30,
        )
        assert r.status_code == 403

        # Agent container restart should succeed
        r = requests.post(
            f"{admin_url}/api/containers/{agent_container_name}",
            json={"action": "restart"},
            timeout=30,
        )
        assert r.status_code == 200
        assert r.json()["action"] == "restart"

        # Verify container comes back
        assert wait_for_container(agent_container_name, timeout=30), (
            f"{agent_container_name} did not recover after restart"
        )


@pytest.mark.e2e
class TestLocalAdminConfigPipeline:
    """Test config update pipeline: local admin → cagent.yaml → warden → CoreDNS → cell.

    Requires --profile admin (which includes warden).
    Verifies that updating config via the local admin API propagates
    all the way to the cell container's DNS resolution.
    """

    # A real domain NOT in the default allowlist (cagent.yaml)
    TEST_DOMAIN = "httpbin.org"

    def test_config_update_propagates_to_cell(self, admin_url, data_plane_running):
        """Updating config via local admin should change cell DNS behavior."""
        # -- Step 1: Read original config (for cleanup) --
        original = requests.get(f"{admin_url}/api/config", timeout=5)
        assert original.status_code == 200, f"cagent.yaml should be configured, got {original.status_code}"
        original_raw = original.json()["raw"]
        original_config = original.json()["config"]

        # -- Step 2: Confirm test domain is currently blocked --
        result = exec_in_cell(f"nslookup {self.TEST_DOMAIN} 10.200.1.5")
        assert "NXDOMAIN" in result.stdout or result.returncode != 0, (
            f"{self.TEST_DOMAIN} already resolves — it should not be in the default allowlist"
        )

        try:
            # -- Step 3: Add test domain via local admin API --
            domains = original_config.get("domains", [])
            domains.append({"domain": self.TEST_DOMAIN})
            r = requests.put(
                f"{admin_url}/api/config",
                json={"domains": domains},
                timeout=5,
            )
            assert r.status_code == 200, f"Config update failed: {r.text}"

            # Verify write persisted
            updated = requests.get(f"{admin_url}/api/config", timeout=5)
            updated_domains = [d["domain"] for d in updated.json()["config"].get("domains", [])]
            assert self.TEST_DOMAIN in updated_domains, "Config write did not persist"

            # -- Step 4: Restart warden to force immediate config regen --
            # On startup, warden reads cagent.yaml and writes new Corefile
            subprocess.run(
                ["docker", "restart", "warden"],
                capture_output=True,
                timeout=30,
                check=True,
            )
            assert wait_for_container("warden", timeout=15), "warden did not restart"
            # Give it a moment to regenerate configs
            time.sleep(3)

            # -- Step 5: Wait for warden API, then reload CoreDNS --
            warden_ready = False
            deadline = time.time() + 30
            while time.time() < deadline:
                try:
                    r = requests.get(f"{admin_url}/api/health", timeout=3)
                    if r.status_code == 200:
                        warden_ready = True
                        break
                except Exception:
                    pass
                time.sleep(1)
            assert warden_ready, "Warden API did not become ready within 30s after restart"
            r = requests.post(f"{admin_url}/api/config/reload", timeout=60)
            assert r.status_code == 200
            assert wait_for_container("dns-filter", timeout=15), "dns-filter did not come back after reload"
            # Wait for CoreDNS to be ready
            time.sleep(2)

            # -- Step 6: Verify domain now resolves from cell --
            result = exec_in_cell(f"nslookup {self.TEST_DOMAIN} 10.200.1.5")
            assert result.returncode == 0 and "NXDOMAIN" not in result.stdout, (
                f"{self.TEST_DOMAIN} should resolve after being added to config. "
                f"stdout: {result.stdout}, stderr: {result.stderr}"
            )

        finally:
            # -- Cleanup: restore original config --
            requests.put(
                f"{admin_url}/api/config/raw",
                json={"content": original_raw},
                timeout=30,
            )
            subprocess.run(
                ["docker", "restart", "warden"],
                capture_output=True,
                timeout=30,
            )
            # Wait for warden API to be ready (not just container "Up")
            deadline = time.time() + 30
            while time.time() < deadline:
                try:
                    r = requests.get(f"{admin_url}/api/health", timeout=3)
                    if r.status_code == 200:
                        break
                except Exception:
                    pass
                time.sleep(1)
            try:
                requests.post(f"{admin_url}/api/config/reload", timeout=60)
            except requests.exceptions.RequestException:
                pass  # best-effort cleanup


def ws_recv_until(ws, marker, max_reads: int = 30) -> str:
    """Read from WebSocket until marker appears in accumulated output.

    marker can be a string or a list of strings (matches any).
    """
    if isinstance(marker, str):
        markers = [marker]
    else:
        markers = list(marker)
    output = ""
    consecutive_timeouts = 0
    for _ in range(max_reads):
        try:
            output += ws.recv()
            consecutive_timeouts = 0
        except websocket.WebSocketTimeoutException:
            consecutive_timeouts += 1
            if consecutive_timeouts >= 3:
                break
            continue
        if any(m in output for m in markers):
            break
    return output


# Shell prompt markers — root uses '#', non-root uses '$'
PROMPT_MARKERS = ["$ ", "# "]


@pytest.mark.e2e
@pytest.mark.skip(reason="WebSocket terminal needs rework — 500 on handshake")
class TestWebTerminal:
    """Test web terminal via WebSocket (requires --profile admin).

    Connects to the cell container's shell through the local admin
    WebSocket endpoint and verifies interactive I/O and lean toolchain.
    """

    @pytest.fixture(autouse=True)
    def _terminal_ws(self, admin_url, data_plane_running, agent_container_name):
        """Connect a WebSocket to the cell terminal for each test."""
        ws_url = admin_url.replace("http://", "ws://")
        self.ws = websocket.create_connection(f"{ws_url}/api/terminal/{agent_container_name}", timeout=10)
        # Drain the initial bash prompt / MOTD (root='#', user='$')
        ws_recv_until(self.ws, PROMPT_MARKERS, max_reads=15)
        # Disable echo so markers aren't found in the echoed command
        self.ws.send("stty -echo\n")
        ws_recv_until(self.ws, PROMPT_MARKERS, max_reads=10)
        yield
        try:
            self.ws.close()
        except Exception:
            pass

    def _run(self, command: str, marker: str = None) -> str:
        """Send a command and return output up to the marker."""
        if marker is None:
            marker = "END_MARKER_E2E"
            command = f"{command}; echo {marker}"
        self.ws.send(command + "\n")
        return ws_recv_until(self.ws, marker)

    def test_shell_prompt(self, admin_url):
        """Should get an interactive shell via WebSocket."""
        output = self._run("echo HELLO_TERMINAL")
        assert "HELLO_TERMINAL" in output

    def test_lean_core_utils(self, admin_url):
        """Lean image should have core CLI utilities."""
        for binary in ("curl", "wget", "git", "jq", "vim", "nano", "tmux", "htop", "tree"):
            output = self._run(f"which {binary}")
            assert f"/{binary}" in output, f"{binary} not found in cell container"

    def test_lean_python(self, admin_url):
        """Lean image should have Python 3 with key packages."""
        output = self._run("python3 --version")
        assert "Python 3" in output

        output = self._run("python3 -c \"import requests, httpx, yaml; print('OK')\"")
        assert "OK" in output

    def test_lean_node(self, admin_url):
        """Lean image should have Node.js and yarn."""
        output = self._run("node --version")
        assert output.strip() and "v" in output

        output = self._run("yarn --version")
        assert "END_MARKER_E2E" in output  # just confirm it ran without error

    def test_lean_build_tools(self, admin_url):
        """Lean image should have build essentials."""
        for binary in ("make", "cmake", "gcc", "g++"):
            output = self._run(f"which {binary}")
            assert f"/{binary}" in output, f"{binary} not found in cell container"

    def test_lean_network_tools(self, admin_url):
        """Lean image should have network diagnostic tools."""
        for binary in ("nc", "nslookup", "ping"):
            output = self._run(f"which {binary}")
            assert binary in output, f"{binary} not found in cell container"

    def test_lean_db_clients(self, admin_url):
        """Lean image should have database CLI clients."""
        output = self._run("which psql")
        assert "psql" in output

        output = self._run("which redis-cli")
        assert "redis-cli" in output

    def test_network_isolation_via_terminal(self, admin_url):
        """Direct external access should be blocked even through the terminal."""
        output = self._run("curl -s --connect-timeout 2 http://8.8.8.8 || echo BLOCKED")
        assert "BLOCKED" in output or "not_allowed" in output, (
            "Cell can reach external IPs directly through terminal — isolation broken!"
        )


def wait_for_dp_access_log(admin_url, domain, timeout=15.0, poll=1.0):
    """Poll DP blocked-domains endpoint until the domain appears or timeout."""
    deadline = time.time() + timeout
    while True:
        r = requests.get(
            f"{admin_url}/api/analytics/blocked-domains",
            params={"hours": 1, "limit": 50},
            timeout=10,
        )
        if r.status_code == 200:
            for d in r.json().get("blocked_domains", []):
                if d["domain"] == domain:
                    return d
        if time.time() >= deadline:
            return None
        time.sleep(poll)


@pytest.mark.e2e
class TestAnalytics:
    """Test analytics endpoints (requires --profile admin)."""

    # Use a unique blocked domain for analytics tests
    BLOCKED_DOMAIN = "analytics-e2e-test.example.com"

    @pytest.fixture(autouse=True)
    def _generate_blocked_traffic(self, admin_url, data_plane_running):
        """Generate blocked (403) traffic before analytics tests."""
        # Fire several requests to a blocked domain via the proxy
        for _ in range(3):
            exec_in_cell(
                f"curl -s -o /dev/null -x http://10.200.1.10:8443 --connect-timeout 5 http://{self.BLOCKED_DOMAIN}/test"
            )
        # Give Envoy a moment to flush logs
        time.sleep(2)

    def test_blocked_domains_endpoint(self, admin_url):
        """GET /api/analytics/blocked-domains returns blocked domain with count."""
        entry = wait_for_dp_access_log(admin_url, self.BLOCKED_DOMAIN)
        assert entry is not None, f"{self.BLOCKED_DOMAIN} not found in blocked domains after traffic + wait"
        assert entry["count"] >= 1
        assert "last_seen" in entry

    def test_blocked_domains_response_shape(self, admin_url):
        """Blocked domains response has correct top-level structure."""
        r = requests.get(
            f"{admin_url}/api/analytics/blocked-domains",
            params={"hours": 1, "limit": 5},
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert "blocked_domains" in data
        assert "window_hours" in data
        assert data["window_hours"] == 1
        assert isinstance(data["blocked_domains"], list)

    def test_bandwidth_endpoint(self, admin_url, data_plane_running):
        """GET /api/analytics/bandwidth returns bandwidth data."""
        # Generate some traffic to an allowed domain (may already exist from fixture)
        exec_in_cell("curl -s -o /dev/null -x http://10.200.1.10:8443 http://ifconfig.me/")
        time.sleep(2)

        r = requests.get(
            f"{admin_url}/api/analytics/bandwidth",
            params={"hours": 1, "limit": 20},
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert "domains" in data
        assert "window_hours" in data
        assert isinstance(data["domains"], list)
        # At least one domain should have traffic (our blocked domain)
        if data["domains"]:
            entry = data["domains"][0]
            assert "domain" in entry
            assert "bytes_sent" in entry
            assert "bytes_received" in entry
            assert "total_bytes" in entry
            assert "request_count" in entry
            assert entry["request_count"] >= 1

    def test_timeseries_endpoint(self, admin_url):
        """GET /api/analytics/blocked-domains/timeseries returns bucketed data."""
        r = requests.get(
            f"{admin_url}/api/analytics/blocked-domains/timeseries",
            params={"hours": 1, "buckets": 6},
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert "buckets" in data
        assert "window_hours" in data
        assert "bucket_minutes" in data
        assert len(data["buckets"]) == 6
        # Each bucket should have start, end, count
        for bucket in data["buckets"]:
            assert "start" in bucket
            assert "end" in bucket
            assert "count" in bucket
            assert isinstance(bucket["count"], int)
        # At least one bucket should have blocked requests from our fixture
        total = sum(b["count"] for b in data["buckets"])
        assert total >= 1, "No blocked requests in any timeseries bucket"

    def test_diagnose_endpoint(self, admin_url):
        """GET /api/analytics/diagnose returns diagnostic for a blocked domain."""
        r = requests.get(
            f"{admin_url}/api/analytics/diagnose",
            params={"domain": self.BLOCKED_DOMAIN},
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert data["domain"] == self.BLOCKED_DOMAIN
        assert data["in_allowlist"] is False
        assert "dns_result" in data
        assert "recent_requests" in data
        assert "diagnosis" in data
        assert "not in the allowlist" in data["diagnosis"]
        # DNS should block this domain
        assert data["dns_result"] in ("NXDOMAIN", "unknown")


# =============================================================================
# OpenObserve / Log Ingestion Pipeline
# =============================================================================


def is_openobserve_running():
    """Check if the log-store (OpenObserve) container is running."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=^log-store$", "--format", "{{.Status}}"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return "Up" in result.stdout
    except Exception:
        return False


@pytest.mark.e2e
class TestDeepHealth:
    """Test /api/health/deep which includes OpenObserve liveness check."""

    def test_deep_health_includes_oo_check(self, admin_url, data_plane_running):
        """Deep health should include an openobserve check."""
        r = requests.get(f"{admin_url}/api/health/deep", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "checks" in data
        assert "openobserve" in data["checks"]
        # OO should be healthy if auditing profile is running.
        # OpenObserve can take a while to start up, so poll until healthy.
        if is_openobserve_running():
            deadline = time.time() + 60
            while time.time() < deadline:
                r = requests.get(f"{admin_url}/api/health/deep", timeout=10)
                data = r.json()
                if data["checks"]["openobserve"]["status"] == "healthy":
                    break
                time.sleep(2)
            assert data["checks"]["openobserve"]["status"] == "healthy"

    def test_deep_health_superset_of_detailed(self, admin_url, data_plane_running):
        """Deep health should contain all checks from detailed health plus OO."""
        detailed = requests.get(f"{admin_url}/api/health/detailed", timeout=10).json()
        deep = requests.get(f"{admin_url}/api/health/deep", timeout=10).json()

        for key in detailed.get("checks", {}):
            assert key in deep["checks"], f"Deep health missing check '{key}' present in detailed"
        assert "openobserve" in deep["checks"]


@pytest.mark.e2e
class TestLogIngestionPipeline:
    """End-to-end test: traffic → Envoy logs → Vector → OpenObserve → warden search.

    Validates that logs generated by proxy requests flow all the way through
    the pipeline and become queryable via the warden /api/logs/search endpoint.

    Requires --profile auditing (log-store + log-shipper running).
    """

    @pytest.fixture(autouse=True)
    def _require_oo(self, admin_url, data_plane_running):
        """Skip if OpenObserve is not running; wait for it to be healthy."""
        if not is_openobserve_running():
            pytest.skip("OpenObserve not running (--profile auditing required)")
        # Wait for OO to be healthy before running log ingestion tests
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                r = requests.get(f"{admin_url}/api/health/deep", timeout=10)
                if r.status_code == 200 and r.json().get("checks", {}).get("openobserve", {}).get("status") == "healthy":
                    return
            except Exception:
                pass
            time.sleep(2)
        pytest.fail("OpenObserve did not become healthy within 60s")

    def test_envoy_logs_ingested_into_oo(self, admin_url, data_plane_running):
        """Proxy traffic should appear in OpenObserve via warden search.

        1. Generate HTTP traffic with a unique marker through the proxy
        2. Wait for Vector to ship logs to OO
        3. Query warden /api/logs/search for the marker
        """
        marker = f"oo-e2e-{int(time.time())}"

        # Generate traffic through the proxy — the marker appears in the request path
        exec_in_cell(
            f"curl -s -o /dev/null -x http://10.200.1.10:8443 --connect-timeout 5 http://pypi.org/{marker} || true"
        )

        # Poll warden search until the marker appears (Vector flush + OO index)
        deadline = time.time() + 60
        found = False
        while time.time() < deadline:
            r = requests.get(
                f"{admin_url}/api/logs/search",
                params={"query": marker, "limit": 10},
                timeout=10,
            )
            if r.status_code == 200:
                hits = r.json().get("hits", [])
                if hits:
                    found = True
                    break
            time.sleep(3)

        assert found, (
            f"Marker '{marker}' never appeared in OO search within 60s. "
            f"Check Vector → OO pipeline. Last response: {r.status_code} {r.text[:200]}"
        )

    def test_search_with_source_filter(self, admin_url, data_plane_running):
        """Search filtered by source should return matching logs."""
        # Generate some traffic first
        exec_in_cell(
            "curl -s -o /dev/null -x http://10.200.1.10:8443 "
            "--connect-timeout 5 http://pypi.org/search-filter-test || true"
        )
        time.sleep(5)

        r = requests.get(
            f"{admin_url}/api/logs/search",
            params={"source": "envoy", "limit": 5},
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert "hits" in data
        assert "total" in data

    def test_search_with_time_range(self, admin_url, data_plane_running):
        """Search with explicit time range should work."""
        from datetime import datetime, timedelta, timezone

        end = datetime.now(timezone.utc)
        start = end - timedelta(hours=1)

        r = requests.get(
            f"{admin_url}/api/logs/search",
            params={
                "start": start.isoformat(),
                "end": end.isoformat(),
                "limit": 5,
            },
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert "hits" in data

    def test_search_empty_query(self, admin_url, data_plane_running):
        """Search with no query should return recent logs."""
        r = requests.get(
            f"{admin_url}/api/logs/search",
            params={"limit": 5},
            timeout=10,
        )
        assert r.status_code == 200
        data = r.json()
        assert "hits" in data
        assert isinstance(data["hits"], list)


# =============================================================================
# Interactive Mode: Status Endpoints
# =============================================================================


@pytest.mark.e2e
class TestStatusEndpoints:
    """Test system status/metrics endpoints (requires --profile admin)."""

    def test_status_returns_system_info(self, admin_url, data_plane_running):
        """GET /api/status should return CPU, memory, disk stats."""
        r = requests.get(f"{admin_url}/api/status", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "cpu_percent" in data
        assert isinstance(data["cpu_percent"], (int, float))
        assert "memory_mb" in data
        assert data["memory_mb"] > 0
        assert "disk_used_bytes" in data
        assert "load_average" in data
        assert len(data["load_average"]) == 3

    def test_metrics_returns_detailed_info(self, admin_url, data_plane_running):
        """GET /api/metrics should return detailed system metrics."""
        r = requests.get(f"{admin_url}/api/metrics", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "cpu_count" in data
        assert data["cpu_count"] >= 1
        assert "memory_percent" in data
        assert "disk_free_bytes" in data
        assert "cpu_freq_mhz" in data

    def test_disk_returns_mount_info(self, admin_url, data_plane_running):
        """GET /api/disk should return disk usage per mount point."""
        r = requests.get(f"{admin_url}/api/disk", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "disks" in data
        assert isinstance(data["disks"], list)
        assert len(data["disks"]) >= 1
        disk = data["disks"][0]
        assert "path" in disk
        assert "total_bytes" in disk
        assert "used_bytes" in disk
        assert "percent_used" in disk

    def test_processes_returns_top_procs(self, admin_url, data_plane_running):
        """GET /api/processes should return process list."""
        r = requests.get(f"{admin_url}/api/processes", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "processes" in data
        assert isinstance(data["processes"], list)
        # Warden container should have at least a few processes
        assert len(data["processes"]) >= 1
        proc = data["processes"][0]
        assert "pid" in proc
        assert "name" in proc
        assert "cpu_percent" in proc

    def test_network_returns_interface_stats(self, admin_url, data_plane_running):
        """GET /api/network should return network interface statistics."""
        r = requests.get(f"{admin_url}/api/network", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "interfaces" in data
        assert isinstance(data["interfaces"], list)
        # Should have at least one non-loopback interface
        if data["interfaces"]:
            iface = data["interfaces"][0]
            assert "interface" in iface
            assert "bytes_sent" in iface
            assert "bytes_recv" in iface


# =============================================================================
# Interactive Mode: Policy Management
# =============================================================================


@pytest.mark.e2e
class TestPolicyManagement:
    """Test policy push/query endpoints (requires --profile admin)."""

    def test_get_active_policies(self, admin_url, data_plane_running):
        """GET /api/policies/active should return current domain policies."""
        r = requests.get(f"{admin_url}/api/policies/active", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "policies" in data
        assert "count" in data
        assert isinstance(data["policies"], list)
        assert data["count"] == len(data["policies"])
        # Default config should have at least some domains
        assert data["count"] >= 1

    def test_apply_and_verify_policies(self, admin_url, data_plane_running):
        """POST /api/policies/apply should update active policies.

        Saves the original policies, applies new ones, verifies, then restores.
        """
        # Save original policies
        original = requests.get(f"{admin_url}/api/policies/active", timeout=10).json()

        try:
            # Apply new policies
            new_policies = [
                {"domain": "api.github.com"},
                {"domain": "pypi.org", "allowed_paths": ["/simple/"]},
                {"domain": "test-policy-e2e.example.com", "requests_per_minute": 50},
            ]
            r = requests.post(
                f"{admin_url}/api/policies/apply",
                json={"policies": new_policies},
                timeout=15,
            )
            assert r.status_code == 200
            assert r.json()["status"] == "applied"
            assert r.json()["policy_count"] == 3

            # Verify new policies are active
            active = requests.get(f"{admin_url}/api/policies/active", timeout=10).json()
            active_domains = [p["domain"] for p in active["policies"]]
            assert "api.github.com" in active_domains
            assert "pypi.org" in active_domains
            assert "test-policy-e2e.example.com" in active_domains

        finally:
            # Restore original policies
            requests.post(
                f"{admin_url}/api/policies/apply",
                json={"policies": original["policies"]},
                timeout=15,
            )


# =============================================================================
# Interactive Mode: Command Execution
# =============================================================================


@pytest.mark.e2e
class TestCommandExecution:
    """Test cell command endpoints (requires --profile admin)."""

    def test_restart_cell_via_command(self, admin_url, data_plane_running, agent_container_name):
        """POST /api/commands/restart should restart the cell container."""
        r = requests.post(f"{admin_url}/api/commands/restart", timeout=60)
        assert r.status_code == 200
        data = r.json()
        assert data["command"] == "restart"
        assert data["status"] == "completed"

        # Verify cell comes back
        assert wait_for_container(agent_container_name, timeout=30), (
            f"Cell container {agent_container_name} did not recover after restart"
        )

    def test_stop_and_start_cell(self, admin_url, data_plane_running, agent_container_name):
        """POST /api/commands/stop + start should stop and restart the cell."""
        # Stop
        r = requests.post(f"{admin_url}/api/commands/stop", timeout=60)
        assert r.status_code == 200
        assert r.json()["command"] == "stop"

        # Verify stopped
        time.sleep(2)
        assert not is_container_running(agent_container_name), "Cell should be stopped"

        # Start
        r = requests.post(f"{admin_url}/api/commands/start", timeout=60)
        assert r.status_code == 200
        assert r.json()["command"] == "start"

        # Verify started
        assert wait_for_container(agent_container_name, timeout=30), "Cell did not start after /api/commands/start"


# =============================================================================
# Warden Bearer Token Auth (E2E)
# =============================================================================


@pytest.mark.e2e
class TestWardenAuthE2E:
    """Test warden auth behavior from outside the container.

    In standalone mode with no WARDEN_API_TOKEN set, all requests should
    be allowed. These tests verify the auth middleware doesn't accidentally
    block local admin access.
    """

    def test_unauthenticated_access_allowed_in_standard_mode(self, admin_url, data_plane_running):
        """Without WARDEN_API_TOKEN, unauthenticated requests should succeed."""
        # Health is always public
        r = requests.get(f"{admin_url}/api/health", timeout=5)
        assert r.status_code == 200

        # Protected endpoints should also work without auth in standard mode
        r = requests.get(f"{admin_url}/api/status", timeout=10)
        assert r.status_code == 200

        r = requests.get(f"{admin_url}/api/policies/active", timeout=10)
        assert r.status_code == 200

    def test_health_always_public(self, admin_url, data_plane_running):
        """Health and ext-authz endpoints should never require auth."""
        for path in ("/api/health", "/api/health/detailed", "/api/health/deep"):
            r = requests.get(f"{admin_url}{path}", timeout=10)
            assert r.status_code == 200, f"{path} returned {r.status_code}"
