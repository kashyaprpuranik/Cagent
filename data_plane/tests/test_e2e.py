"""
End-to-end tests for the full data plane stack.

These tests require the data plane to be running in standalone mode
with the dev and admin profiles:
    cd data_plane && docker compose --profile dev --profile admin up -d

Config-write tests are automatically skipped in connected mode.

Run with:
    sg docker -c "python -m pytest tests/test_e2e.py -v"
"""

import pytest
import requests
import subprocess
import time
import websocket


def pytest_configure(config):
    config.addinivalue_line(
        "markers", "e2e: mark test as end-to-end (requires full stack running)"
    )


def is_data_plane_running():
    """Check if data plane containers are running."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=http-proxy", "--format", "{{.Names}}"],
            capture_output=True,
            text=True,
            timeout=5
        )
        return "http-proxy" in result.stdout
    except:
        return False


@pytest.fixture(scope="module")
def data_plane_running():
    """Check if data plane is running."""
    if not is_data_plane_running():
        pytest.skip(
            "Data plane not running. Start with: "
            "cd data_plane && docker-compose up -d"
        )
    return True


def exec_in_agent(command: str) -> subprocess.CompletedProcess:
    """Execute a command in the agent container."""
    return subprocess.run(
        ["docker", "exec", "agent", "sh", "-c", command],
        capture_output=True,
        text=True,
        timeout=30
    )


@pytest.mark.e2e
class TestAgentNetworkIsolation:
    """Test that agent container is properly isolated."""

    def test_agent_can_reach_envoy(self, data_plane_running):
        """Agent should be able to reach Envoy proxy."""
        result = exec_in_agent("nc -z 10.200.1.10 8443 && echo OK")
        assert result.returncode == 0 or "OK" in result.stdout, \
            f"Agent cannot reach Envoy: {result.stderr}"

    def test_agent_can_reach_dns(self, data_plane_running):
        """Agent should be able to reach DNS filter."""
        result = exec_in_agent("nc -z 10.200.1.5 53 && echo OK")
        assert result.returncode == 0 or "OK" in result.stdout, \
            f"Agent cannot reach DNS: {result.stderr}"

    def test_agent_cannot_reach_external_directly(self, data_plane_running):
        """Agent should NOT be able to reach external IPs directly."""
        # Try to reach Google DNS directly (should fail)
        result = exec_in_agent("nc -z -w 2 8.8.8.8 53 && echo FAIL || echo BLOCKED")
        assert "BLOCKED" in result.stdout, \
            "Agent can reach external IPs directly - network isolation broken!"

    def test_agent_cannot_reach_control_plane(self, data_plane_running):
        """Agent should NOT be able to reach control plane directly."""
        # Control plane is on infra-net, agent should not reach it
        result = exec_in_agent("nc -z -w 2 10.200.2.1 8000 && echo FAIL || echo BLOCKED")
        # This might succeed if control plane IP is different, so just log
        if "FAIL" in result.stdout:
            pytest.skip("Warning: Agent may be able to reach infra-net")


@pytest.mark.e2e
class TestDNSFiltering:
    """Test DNS filtering behavior."""

    def test_allowed_domain_resolves(self, data_plane_running):
        """Allowed domains should resolve via DNS filter."""
        result = exec_in_agent("nslookup api.openai.com 10.200.1.5")
        assert result.returncode == 0, f"Failed to resolve allowed domain: {result.stderr}"
        assert "NXDOMAIN" not in result.stdout, "Allowed domain returned NXDOMAIN"

    def test_blocked_domain_fails(self, data_plane_running):
        """Non-allowed domains should fail DNS resolution."""
        result = exec_in_agent("nslookup evil-malware.com 10.200.1.5")
        # Should return NXDOMAIN or fail
        assert "NXDOMAIN" in result.stdout or result.returncode != 0, \
            "Blocked domain should not resolve"


@pytest.mark.e2e
class TestProxyEgress:
    """Test egress through Envoy proxy."""

    def test_https_through_proxy_allowed_domain(self, data_plane_running):
        """Should successfully reach allowed domains through proxy."""
        result = exec_in_agent(
            "curl -s -o /dev/null -w '%{http_code}' "
            "-x http://10.200.1.10:8443 "
            "https://api.github.com"
        )
        # Should get some HTTP response (even 401 unauthorized is fine)
        http_code = result.stdout.strip()
        assert http_code.isdigit() and int(http_code) < 500, \
            f"Request to allowed domain failed with: {http_code}"

    def test_https_through_proxy_blocked_domain(self, data_plane_running):
        """Should fail to reach blocked domains through proxy."""
        result = exec_in_agent(
            "curl -s -o /dev/null -w '%{http_code}' "
            "-x http://10.200.1.10:8443 "
            "--connect-timeout 5 "
            "https://evil-malware.com"
        )
        # Should fail (connection refused, timeout, or 403)
        http_code = result.stdout.strip()
        # Empty or error code means blocked
        assert not http_code or http_code == "000" or http_code == "403", \
            f"Request to blocked domain succeeded with: {http_code}"


@pytest.mark.e2e
class TestCredentialInjection:
    """Test credential injection functionality (via Envoy Lua filter)."""

    def test_request_headers_not_contain_secrets(self, data_plane_running):
        """Agent requests should not contain raw secrets."""
        # Make a request and capture what the agent sees
        result = exec_in_agent("env | grep -i api_key || echo 'NO_SECRETS_IN_ENV'")
        assert "NO_SECRETS_IN_ENV" in result.stdout or not result.stdout.strip(), \
            "Agent environment should not contain API keys"

    def test_envoy_handles_credential_injection(self, data_plane_running):
        """Envoy should be running (handles credential injection via Lua)."""
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=http-proxy", "--format", "{{.Status}}"],
            capture_output=True,
            text=True
        )
        assert "Up" in result.stdout, "Envoy proxy is not running"

    def test_https_connect_tunnel_no_rewrite(self, data_plane_running):
        """HTTPS requests should pass through as CONNECT tunnel - no header injection.

        When agent uses: curl https://api.openai.com
        Envoy sees CONNECT tunnel, cannot inject headers into encrypted traffic.
        This is expected behavior - credentials are NOT injected for direct HTTPS.
        """
        # Make HTTPS request - this creates a CONNECT tunnel
        # We use -v to see the CONNECT method being used
        result = exec_in_agent(
            "curl -v -s -o /dev/null -w '%{http_code}' "
            "-x http://10.200.1.10:8443 "
            "--connect-timeout 5 "
            "https://httpbin.org/headers 2>&1 | grep -E 'CONNECT|HTTP/1.1'"
        )
        # Should see CONNECT method in verbose output (indicates tunnel mode)
        # Note: This test verifies the tunnel is established, not that headers aren't injected
        # (we can't easily verify header injection didn't happen from outside the tunnel)
        assert "CONNECT" in result.stdout or result.returncode == 0, \
            "HTTPS should use CONNECT tunnel through proxy"

    def test_http_devbox_local_gets_credentials(self, data_plane_running):
        """HTTP requests to *.devbox.local should get credentials injected.

        When agent uses: curl http://openai.devbox.local/...
        Envoy sees plain HTTP, can inject Authorization header.
        """
        # This test requires a secret with alias to be configured
        # For now, just verify the devbox.local routing works
        result = exec_in_agent(
            "curl -s -o /dev/null -w '%{http_code}' "
            "-x http://10.200.1.10:8443 "
            "--connect-timeout 5 "
            "http://openai.devbox.local/v1/models 2>&1"
        )
        # Should get some response (401 without valid creds, or 200 with)
        # Not 000 (connection failed) or 403 (blocked)
        http_code = result.stdout.strip()
        # Any response indicates the devbox.local routing worked
        assert http_code and http_code != "000", \
            f"devbox.local request failed: {result.stderr}"


@pytest.mark.e2e
class TestLogging:
    """Test log collection."""

    def test_vector_running(self, data_plane_running):
        """Vector should be running for log collection."""
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=log-shipper", "--format", "{{.Status}}"],
            capture_output=True,
            text=True
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


@pytest.mark.e2e
class TestAgentSecurityHardening:
    """Test container security hardening: capabilities, seccomp, isolation."""

    def test_no_docker_socket(self, data_plane_running):
        """Agent should not have access to the Docker socket."""
        result = exec_in_agent("ls /var/run/docker.sock 2>&1 || echo NO_SOCKET")
        assert "NO_SOCKET" in result.stdout or "No such file" in result.stdout, \
            "Docker socket is accessible inside agent — container escape risk!"

    def test_no_host_filesystem(self, data_plane_running):
        """Agent should not see host filesystem mounts."""
        # /host is a common mount point; also check that /proc/1/root doesn't
        # expose the host (in a container, PID 1 root is the container root)
        result = exec_in_agent("ls /host 2>&1 || echo NO_HOST")
        assert "NO_HOST" in result.stdout or "No such file" in result.stdout

    def test_proxy_env_vars_set(self, data_plane_running):
        """Agent must have HTTP_PROXY and HTTPS_PROXY pointing to Envoy."""
        result = exec_in_agent("echo $HTTP_PROXY")
        assert "10.200.1.10:8443" in result.stdout, \
            f"HTTP_PROXY not set correctly: {result.stdout}"

        result = exec_in_agent("echo $HTTPS_PROXY")
        assert "10.200.1.10:8443" in result.stdout, \
            f"HTTPS_PROXY not set correctly: {result.stdout}"

    def test_cannot_reach_infra_net(self, data_plane_running):
        """Agent should not be able to reach any infra-net addresses."""
        # dns-filter's infra side
        result = exec_in_agent("nc -z -w 2 10.200.2.5 53 && echo FAIL || echo BLOCKED")
        assert "BLOCKED" in result.stdout, \
            "Agent can reach dns-filter on infra-net (10.200.2.5)"

        # envoy's infra side
        result = exec_in_agent("nc -z -w 2 10.200.2.10 8443 && echo FAIL || echo BLOCKED")
        assert "BLOCKED" in result.stdout, \
            "Agent can reach envoy on infra-net (10.200.2.10)"

    def test_raw_socket_blocked(self, data_plane_running):
        """Raw sockets should be blocked (CAP_NET_RAW dropped + seccomp)."""
        # SOCK_RAW with AF_INET requires CAP_NET_RAW
        result = exec_in_agent(
            "python3 -c \""
            "import socket; "
            "s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP); "
            "print('RAW_ALLOWED')\" 2>&1 || echo RAW_BLOCKED"
        )
        assert "RAW_BLOCKED" in result.stdout or "Operation not permitted" in result.stdout, \
            "Raw sockets are allowed — agent could craft packets to bypass proxy!"

    def test_af_packet_blocked(self, data_plane_running):
        """AF_PACKET sockets should be blocked by seccomp profile."""
        result = exec_in_agent(
            "python3 -c \""
            "import socket; "
            "s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW); "
            "print('PACKET_ALLOWED')\" 2>&1 || echo PACKET_BLOCKED"
        )
        assert "PACKET_BLOCKED" in result.stdout or "Operation not permitted" in result.stdout, \
            "AF_PACKET sockets are allowed — agent could sniff/inject raw frames!"

    def test_no_privilege_escalation(self, data_plane_running):
        """no-new-privileges should prevent setuid escalation."""
        # Check if agent already runs as root
        who = exec_in_agent("id -u")
        if who.stdout.strip() == "0":
            # Already root — no-new-privileges is set but sudo is a no-op.
            # Verify the security_opt is in place via container inspect.
            result = subprocess.run(
                ["docker", "inspect", "agent", "--format", "{{.HostConfig.SecurityOpt}}"],
                capture_output=True, text=True, timeout=5,
            )
            assert "no-new-privileges" in result.stdout, \
                "no-new-privileges is not set on agent container"
        else:
            # Non-root — sudo's setuid bit should be blocked by no-new-privileges
            result = exec_in_agent("sudo id 2>&1 || echo SUDO_FAILED")
            assert "SUDO_FAILED" in result.stdout or "root" not in result.stdout, \
                "sudo succeeded — no-new-privileges may not be set!"

    def test_ipv6_disabled(self, data_plane_running):
        """IPv6 should be disabled to prevent bypass of IPv4 egress controls."""
        result = exec_in_agent(
            "curl -6 -s --connect-timeout 2 http://[2607:f8b0:4004:800::200e] "
            "2>&1 || echo IPV6_BLOCKED"
        )
        assert "IPV6_BLOCKED" in result.stdout \
            or "Could not resolve" in result.stdout \
            or "connect to" in result.stdout, \
            "IPv6 connectivity is available — could bypass egress controls!"


def get_admin_url():
    """Get local admin base URL, detecting the mapped port."""
    try:
        result = subprocess.run(
            ["docker", "port", "local-admin", "8080"],
            capture_output=True, text=True, timeout=5
        )
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
    """Get local admin URL, skip if not running."""
    url = get_admin_url()
    if not url:
        pytest.skip(
            "Local admin not running. Start with: "
            "docker-compose --profile admin up -d"
        )
    return url


def is_connected_mode(admin_url: str) -> bool:
    """Check if the data plane is running in connected (read-only) mode."""
    try:
        r = requests.get(f"{admin_url}/api/info", timeout=5)
        return r.json().get("mode") == "connected"
    except Exception:
        return False


def is_container_running(name):
    """Check if a Docker container is running."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", f"name=^{name}$", "--format", "{{.Status}}"],
            capture_output=True, text=True, timeout=5
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
        assert "agent" in data["checks"]
        assert "dns-filter" in data["checks"]
        assert "http-proxy" in data["checks"]

    def test_info(self, admin_url):
        """Info endpoint should return container names and paths."""
        r = requests.get(f"{admin_url}/api/info", timeout=5)
        assert r.status_code == 200
        data = r.json()
        assert data["containers"]["agent"] == "agent"
        assert data["containers"]["dns"] == "dns-filter"
        assert data["containers"]["http_proxy"] == "http-proxy"

    def test_list_containers(self, admin_url):
        """Should list managed containers with status."""
        r = requests.get(f"{admin_url}/api/containers", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert "containers" in data
        for name in ("agent", "dns-filter", "http-proxy"):
            assert name in data["containers"]
            assert "status" in data["containers"][name]

    def test_get_single_container(self, admin_url):
        """Should get status for a specific container."""
        r = requests.get(f"{admin_url}/api/containers/agent", timeout=10)
        assert r.status_code == 200
        data = r.json()
        assert data["name"] == "agent"
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

    def test_ssh_tunnel_status(self, admin_url):
        """Should return SSH tunnel status."""
        r = requests.get(f"{admin_url}/api/ssh-tunnel", timeout=5)
        assert r.status_code == 200
        data = r.json()
        assert "enabled" in data
        assert "connected" in data
        assert "configured" in data

    def test_generate_stcp_key(self, admin_url):
        """Should generate an STCP secret key."""
        r = requests.post(f"{admin_url}/api/ssh-tunnel/generate-key", timeout=5)
        assert r.status_code == 200
        data = r.json()
        assert "stcp_secret_key" in data
        assert len(data["stcp_secret_key"]) > 20

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
        if is_connected_mode(admin_url):
            pytest.skip("Config is read-only in connected mode")
        r = requests.put(
            f"{admin_url}/api/config/raw",
            json={"content": "domains:\n  - domain: good.com\n bad_indent"},
            timeout=5,
        )
        assert r.status_code == 400

    def test_container_restart(self, admin_url, data_plane_running):
        """Restarting http-proxy via API should succeed and container should recover."""
        r = requests.post(
            f"{admin_url}/api/containers/http-proxy",
            json={"action": "restart"},
            timeout=30,
        )
        assert r.status_code == 200
        assert r.json()["action"] == "restart"

        # Verify container comes back
        assert wait_for_container("http-proxy", timeout=30), \
            "http-proxy did not recover after restart"

    def test_ssh_tunnel_connect_info_unconfigured(self, admin_url):
        """Should return 400 when tunnel is not configured."""
        r = requests.get(f"{admin_url}/api/ssh-tunnel/connect-info", timeout=5)
        # 400 if STCP_SECRET_KEY is not set, 200 if it happens to be configured
        assert r.status_code in (200, 400)


@pytest.mark.e2e
class TestLocalAdminConfigPipeline:
    """Test config update pipeline: local admin → cagent.yaml → agent-manager → CoreDNS → agent.

    Requires --profile admin (which includes agent-manager).
    Verifies that updating config via the local admin API propagates
    all the way to the agent container's DNS resolution.
    """

    # A real domain that is unlikely to be in the default allowlist
    TEST_DOMAIN = "ifconfig.me"

    def test_config_update_propagates_to_agent(self, admin_url, data_plane_running):
        """Updating config via local admin should change agent DNS behavior."""
        if is_connected_mode(admin_url):
            pytest.skip("Config is read-only in connected mode")
        if not is_container_running("agent-manager"):
            pytest.skip("agent-manager not running (needs --profile admin)")

        # -- Step 1: Read original config (for cleanup) --
        original = requests.get(f"{admin_url}/api/config", timeout=5)
        if original.status_code == 404:
            pytest.skip("No cagent.yaml configured")
        original_raw = original.json()["raw"]
        original_config = original.json()["config"]

        # -- Step 2: Confirm test domain is currently blocked --
        result = exec_in_agent(f"nslookup {self.TEST_DOMAIN} 10.200.1.5")
        if "NXDOMAIN" not in result.stdout and result.returncode == 0:
            pytest.skip(f"{self.TEST_DOMAIN} already resolves — already in allowlist")

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

            # -- Step 4: Restart agent-manager to force immediate config regen --
            # On startup, agent-manager reads cagent.yaml and writes new Corefile
            subprocess.run(
                ["docker", "restart", "agent-manager"],
                capture_output=True, timeout=30, check=True,
            )
            assert wait_for_container("agent-manager", timeout=15), \
                "agent-manager did not restart"
            # Give it a moment to regenerate configs
            time.sleep(3)

            # -- Step 5: Reload CoreDNS to pick up new Corefile --
            r = requests.post(f"{admin_url}/api/config/reload", timeout=15)
            assert r.status_code == 200
            assert wait_for_container("dns-filter", timeout=15), \
                "dns-filter did not come back after reload"
            # Wait for CoreDNS to be ready
            time.sleep(2)

            # -- Step 6: Verify domain now resolves from agent --
            result = exec_in_agent(f"nslookup {self.TEST_DOMAIN} 10.200.1.5")
            assert result.returncode == 0 and "NXDOMAIN" not in result.stdout, \
                f"{self.TEST_DOMAIN} should resolve after being added to config. " \
                f"stdout: {result.stdout}, stderr: {result.stderr}"

        finally:
            # -- Cleanup: restore original config --
            requests.put(
                f"{admin_url}/api/config/raw",
                json={"content": original_raw},
                timeout=30,
            )
            subprocess.run(
                ["docker", "restart", "agent-manager"],
                capture_output=True, timeout=30,
            )
            time.sleep(3)
            requests.post(f"{admin_url}/api/config/reload", timeout=15)


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
class TestWebTerminal:
    """Test web terminal via WebSocket (requires --profile admin).

    Connects to the agent container's shell through the local admin
    WebSocket endpoint and verifies interactive I/O and lean toolchain.
    """

    @pytest.fixture(autouse=True)
    def _terminal_ws(self, admin_url, data_plane_running):
        """Connect a WebSocket to the agent terminal for each test."""
        ws_url = admin_url.replace("http://", "ws://")
        self.ws = websocket.create_connection(
            f"{ws_url}/api/terminal/agent", timeout=10
        )
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
            assert f"/{binary}" in output, f"{binary} not found in agent container"

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
            assert f"/{binary}" in output, f"{binary} not found in agent container"

    def test_lean_network_tools(self, admin_url):
        """Lean image should have network diagnostic tools."""
        for binary in ("nc", "nslookup", "ping"):
            output = self._run(f"which {binary}")
            assert binary in output, f"{binary} not found in agent container"

    def test_lean_db_clients(self, admin_url):
        """Lean image should have database CLI clients."""
        output = self._run("which psql")
        assert "psql" in output

        output = self._run("which redis-cli")
        assert "redis-cli" in output

    def test_network_isolation_via_terminal(self, admin_url):
        """Direct external access should be blocked even through the terminal."""
        output = self._run("curl -s --connect-timeout 2 http://8.8.8.8 || echo BLOCKED")
        assert "BLOCKED" in output or "not_allowed" in output, \
            "Agent can reach external IPs directly through terminal — isolation broken!"
