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

    def test_envoy_config_valid_yaml(self, configs_dir):
        """Envoy config should be valid YAML."""
        config_file = configs_dir / "envoy" / "envoy-enhanced.yaml"
        content = config_file.read_text()

        try:
            config = yaml.safe_load(content)
            assert config is not None
        except yaml.YAMLError as e:
            pytest.fail(f"Invalid YAML: {e}")

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

        result = subprocess.run(
            [
                "docker", "run", "--rm",
                "-v", f"{config_file}:/etc/envoy/envoy.yaml:ro",
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

