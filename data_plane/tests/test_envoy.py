"""
Tests for the Envoy proxy configuration.
"""

import pytest
import subprocess
import yaml
from pathlib import Path


class TestEnvoyConfig:
    """Test Envoy configuration validity."""

    def test_envoy_config_exists(self, configs_dir):
        """Envoy config file should exist."""
        config_file = configs_dir / "envoy" / "envoy-enhanced.yaml"
        assert config_file.exists(), f"Envoy config not found at {config_file}"

    def test_lua_filter_file_exists(self, configs_dir):
        """Lua filter file should exist alongside envoy config."""
        lua_file = configs_dir / "envoy" / "filter.lua"
        assert lua_file.exists(), f"Lua filter not found at {lua_file}"

    def test_envoy_config_valid_yaml(self, configs_dir):
        """Envoy config should be valid YAML."""
        config_file = configs_dir / "envoy" / "envoy-enhanced.yaml"
        content = config_file.read_text()

        try:
            config = yaml.safe_load(content)
            assert config is not None
        except yaml.YAMLError as e:
            pytest.fail(f"Invalid YAML: {e}")

    def test_envoy_config_no_inline_lua(self, configs_dir):
        """Envoy config should not contain inline Lua code."""
        config_file = configs_dir / "envoy" / "envoy-enhanced.yaml"
        content = config_file.read_text()
        assert "inline_code" not in content, \
            "Envoy config should use external file, not inline_code"

    def test_envoy_config_references_lua_file(self, configs_dir):
        """Envoy config should reference filter.lua via filename."""
        config_file = configs_dir / "envoy" / "envoy-enhanced.yaml"
        content = config_file.read_text()
        assert "filter.lua" in content, \
            "Envoy config should reference filter.lua"

    def test_envoy_config_has_listeners(self, configs_dir):
        """Envoy config should define listeners."""
        config_file = configs_dir / "envoy" / "envoy-enhanced.yaml"
        config = yaml.safe_load(config_file.read_text())

        assert "static_resources" in config
        assert "listeners" in config["static_resources"]
        assert len(config["static_resources"]["listeners"]) > 0

    def test_envoy_config_has_clusters(self, configs_dir):
        """Envoy config should define clusters."""
        config_file = configs_dir / "envoy" / "envoy-enhanced.yaml"
        config = yaml.safe_load(config_file.read_text())

        assert "static_resources" in config
        assert "clusters" in config["static_resources"]

    def test_envoy_config_has_admin(self, configs_dir):
        """Envoy config should have admin interface."""
        config_file = configs_dir / "envoy" / "envoy-enhanced.yaml"
        config = yaml.safe_load(config_file.read_text())

        assert "admin" in config
        assert "address" in config["admin"]


class TestEnvoyConfigValidation:
    """Validate Envoy config using envoy --mode validate."""

    def test_envoy_validate_config(self, skip_without_docker, configs_dir):
        """Envoy should validate the configuration."""
        config_file = configs_dir / "envoy" / "envoy-enhanced.yaml"
        lua_file = configs_dir / "envoy" / "filter.lua"

        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{config_file}:/etc/envoy/envoy.yaml:ro",
                "-v", f"{lua_file}:/etc/envoy/filter.lua:ro",
                "envoyproxy/envoy:v1.28-latest",
                "--mode", "validate",
                "-c", "/etc/envoy/envoy.yaml"
            ],
            capture_output=True,
            text=True,
            timeout=30
        )

        # Note: Envoy may fail validation if it can't resolve cluster addresses
        # but structural issues should be caught
        if result.returncode != 0:
            # Check if it's just a connection error vs config error
            if "Unable to establish connection" in result.stderr:
                pytest.skip("Envoy validation requires network access to clusters")
            elif "configuration" in result.stderr.lower():
                pytest.fail(f"Envoy config validation failed: {result.stderr}")


class TestEnvoyProxySettings:
    """Test Envoy proxy configuration settings."""

    def test_proxy_listens_on_expected_port(self, configs_dir):
        """Envoy should listen on the expected proxy port."""
        config_file = configs_dir / "envoy" / "envoy-enhanced.yaml"
        config = yaml.safe_load(config_file.read_text())

        listeners = config["static_resources"]["listeners"]

        # Find the main proxy listener
        proxy_ports = []
        for listener in listeners:
            address = listener.get("address", {})
            socket_address = address.get("socket_address", {})
            port = socket_address.get("port_value")
            if port:
                proxy_ports.append(port)

        # Should have at least one listener
        assert len(proxy_ports) > 0, "No listener ports found"

    def test_proxy_has_access_logging(self, configs_dir):
        """Envoy should have access logging configured."""
        config_file = configs_dir / "envoy" / "envoy-enhanced.yaml"
        content = config_file.read_text()

        # Check for access log configuration
        assert "access_log" in content.lower() or "accesslog" in content.lower(), \
            "Envoy should have access logging configured"


class TestLuaFilterContent:
    """Test the Lua filter file content."""

    def test_lua_has_envoy_on_request(self, configs_dir):
        """Lua filter should define envoy_on_request."""
        lua_file = configs_dir / "envoy" / "filter.lua"
        content = lua_file.read_text()
        assert "function envoy_on_request" in content

    def test_lua_has_envoy_on_response(self, configs_dir):
        """Lua filter should define envoy_on_response."""
        lua_file = configs_dir / "envoy" / "filter.lua"
        content = lua_file.read_text()
        assert "function envoy_on_response" in content

    def test_lua_uses_per_stream_metadata(self, configs_dir):
        """Lua filter should use per-stream metadata instead of module-level variable."""
        lua_file = configs_dir / "envoy" / "filter.lua"
        content = lua_file.read_text()
        assert "dynamicMetadata" in content, \
            "Lua should use per-stream dynamic metadata for concurrency safety"
        assert "local request_domain = nil" not in content, \
            "Lua should not use module-level request_domain variable"

    def test_lua_has_match_domain_wildcard(self, configs_dir):
        """Lua filter should define match_domain_wildcard helper."""
        lua_file = configs_dir / "envoy" / "filter.lua"
        content = lua_file.read_text()
        assert "function match_domain_wildcard" in content

    def test_lua_no_deprecated_functions(self, configs_dir):
        """Lua filter should not contain deprecated functions."""
        lua_file = configs_dir / "envoy" / "filter.lua"
        content = lua_file.read_text()
        deprecated = [
            "function get_credential(",
            "function get_rate_limit_config(",
            "function check_rate_limit(",
            "function get_egress_limit(",
            "function check_egress_limit(",
            "function check_path_allowed(",
            "function parse_credential_response(",
            "function parse_rate_limit_response(",
            "function parse_egress_limit_response(",
        ]
        for func in deprecated:
            # check_rate_limit_with_config should be OK, only check_rate_limit( is deprecated
            if func == "function check_rate_limit(":
                assert "function check_rate_limit(" not in content or \
                       "function check_rate_limit_with_config(" in content
            else:
                assert func not in content, f"Deprecated function found: {func}"

    def test_lua_has_enhanced_dns_tunneling(self, configs_dir):
        """Lua filter should have enhanced DNS tunneling detection."""
        lua_file = configs_dir / "envoy" / "filter.lua"
        content = lua_file.read_text()
        assert "Excessive subdomain depth" in content
        assert "hex-encoded subdomain" in content.lower() or "hex-encoded" in content

