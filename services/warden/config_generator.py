"""
Config Generator - Generates CoreDNS and Envoy configs from cagent.yaml

Outputs:
  - configs/coredns/Corefile.generated
  - configs/envoy/envoy.generated.yaml

Config Sources (standalone vs connected mode):
  In standalone mode, cagent.yaml is the sole source of truth.
  In connected mode, warden syncs additional data from the control plane
  and merges it with cagent.yaml (yaml entries take precedence).

  Yaml-only (no CP equivalent):
    - dns (upstream servers, cache_ttl)
    - internal_services[] (devbox.local, etc.)
    - circuit_breakers (max_connections, max_requests, etc.)
    - rate_limits.default (global fallback rate limit)

  CP-synced (connected mode merges with yaml):
    - domains[] — synced via GET /api/v1/domain-policies, merged here
      via set_additional_domains(). Includes allowed_paths, rate_limit,
      timeout, read_only. Credentials are NOT included — ext_authz
      resolves them dynamically per-request.

  CP-synced via heartbeat (not config generation):
    - security.seccomp_profile — pushed via heartbeat response
    - resources (cpu/memory limits) — pushed via heartbeat response

  Gap (CP endpoint exists but warden doesn't sync):
    - email.accounts[] — CP has /api/v1/email-policies but warden
      does not yet sync them (same pattern as domains before this fix)
"""

import hashlib
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

import yaml

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


class ConfigGenerator:
    def __init__(self, config_path: str = "/etc/cagent/cagent.yaml"):
        self.config_path = Path(config_path)
        self.config = {}
        self.last_hash = None
        self._additional_domains = []  # CP-provided domain entries

    def set_additional_domains(self, domains: list):
        """Set additional domain entries (e.g., from control plane policies)."""
        self._additional_domains = domains

    def load_config(self) -> bool:
        """Load cagent.yaml config. Returns True if config changed."""
        if not self.config_path.exists():
            logger.error(f"Config file not found: {self.config_path}")
            return False

        content = self.config_path.read_text()
        content_hash = hashlib.md5(content.encode()).hexdigest()

        if content_hash == self.last_hash:
            return False

        self.config = yaml.safe_load(content)
        self.last_hash = content_hash
        logger.info(f"Loaded config from {self.config_path}")
        return True

    def get_domains(self) -> list:
        """Get list of domain configs, merged with any additional domains."""
        yaml_domains = self.config.get("domains", [])
        if not self._additional_domains:
            return yaml_domains
        # Merge: cagent.yaml takes precedence, additional fills in new domains
        yaml_names = {d.get("domain", "").lower() for d in yaml_domains}
        merged = list(yaml_domains)
        for entry in self._additional_domains:
            if entry.get("domain", "").lower() not in yaml_names:
                merged.append(entry)
        return merged

    def get_internal_services(self) -> list:
        """Get list of internal service names."""
        return self.config.get("internal_services", [])

    def get_email_accounts(self) -> list:
        """Get list of email account configs."""
        return self.config.get("email", {}).get("accounts", [])

    def get_dns_config(self) -> dict:
        """Get DNS configuration."""
        return self.config.get("dns", {"upstream": ["8.8.8.8", "8.8.4.4"], "cache_ttl": 300})

    def get_default_rate_limit(self) -> dict:
        """Get default rate limit config."""
        return self.config.get("rate_limits", {}).get("default", {"requests_per_minute": 120, "burst_size": 20})

    def get_resources(self) -> Optional[dict]:
        """Get resource limits config, or None if not configured."""
        return self.config.get("resources")

    def get_circuit_breaker_defaults(self) -> dict:
        """Get default circuit breaker config."""
        return self.config.get(
            "circuit_breakers",
            {
                "max_connections": 1000,
                "max_pending_requests": 1000,
                "max_requests": 1000,
                "max_retries": 3,
            },
        )

    # =========================================================================
    # CoreDNS Generation
    # =========================================================================

    def generate_corefile(self) -> str:
        """Generate CoreDNS Corefile from config."""
        dns_config = self.get_dns_config()
        upstream = " ".join(dns_config.get("upstream", ["8.8.8.8", "8.8.4.4"]))
        cache_ttl = dns_config.get("cache_ttl", 300)

        lines = [
            "# =============================================================================",
            "# CoreDNS Configuration - Auto-generated from cagent.yaml",
            f"# Generated: {datetime.utcnow().isoformat()}Z",
            "# DO NOT EDIT - changes will be overwritten",
            "# =============================================================================",
            "",
            "# Devbox.local aliases -> Envoy proxy (10.200.1.10)",
            "devbox.local {",
            "    template IN A {",
            '        answer "{{ .Name }} 60 IN A 10.200.1.10"',
            "    }",
            "    template IN AAAA {",
            "        rcode NOERROR",
            "    }",
            "    log",
            "}",
            "",
        ]

        # Collect unique domains (expand wildcards for CoreDNS)
        domains = set()
        for entry in self.get_domains():
            domain = entry.get("domain", "")
            if domain.startswith("*."):
                # Wildcard: add base domain
                base = domain[2:]
                domains.add(base)
            else:
                domains.add(domain)

        # Generate domain blocks
        lines.append("# Allowlisted domains")
        for domain in sorted(domains):
            if not domain:
                continue
            lines.extend(
                [
                    f"{domain} {{",
                    f"    forward . {upstream}",
                    f"    cache {cache_ttl}",
                    "    log",
                    "}",
                    "",
                ]
            )

        # Internal services (Docker DNS)
        lines.append("# Internal services (Docker DNS)")
        for service in self.get_internal_services():
            lines.extend(
                [
                    f"{service} {{",
                    "    forward . 127.0.0.11",
                    "    log",
                    "}",
                    "",
                ]
            )

        # Email proxy internal DNS (if email accounts configured)
        if self.get_email_accounts():
            lines.extend(
                [
                    "email-proxy {",
                    "    forward . 127.0.0.11",
                    "    log",
                    "}",
                    "",
                ]
            )

        # Catch-all block (single . {} block: health, metrics, logging, and NXDOMAIN)
        lines.extend(
            [
                "# Catch-all: health, metrics, and block non-allowlisted domains",
                ". {",
                "    health :8080",
                "    prometheus :9153",
                "",
                "    log . {",
                "        class all",
                "    }",
                "    errors",
                "",
                "    # Return NXDOMAIN for non-allowlisted domains",
                "    template ANY ANY {",
                "        rcode NXDOMAIN",
                "    }",
                "}",
            ]
        )

        return "\n".join(lines)

    # =========================================================================
    # Envoy Generation
    # =========================================================================

    def generate_envoy_config(self) -> dict:
        """Generate Envoy config from cagent.yaml."""
        domains = self.get_domains()
        default_rate_limit = self.get_default_rate_limit()

        # Collect credential headers from all domains for ext_authz config
        credential_headers = {"authorization"}  # always include
        for entry in domains:
            cred = entry.get("credential", {})
            if cred and cred.get("header"):
                credential_headers.add(cred["header"].lower())

        # Build virtual hosts and clusters
        virtual_hosts = []
        clusters = []
        cluster_names = set()

        default_rpm = default_rate_limit.get("requests_per_minute", 120)
        default_burst = default_rate_limit.get("burst_size", 20)

        for entry in domains:
            domain = entry.get("domain", "")
            if not domain:
                continue

            alias = entry.get("alias")
            timeout = entry.get("timeout", "30s")
            read_only = entry.get("read_only", False)
            allowed_paths = entry.get("allowed_paths", [])
            domain_rl = entry.get("rate_limit", {})

            # Generate cluster name from domain
            cluster_name = self._domain_to_cluster_name(domain)

            # Domain patterns for virtual host
            domain_patterns = [domain, f"{domain}:443"]

            # Determine actual upstream domain for tracking
            actual_domain = domain
            if domain.startswith("*."):
                actual_domain = domain[2:]

            # Build routes
            routes = []

            if read_only:
                # Block POST/PUT/DELETE
                for method in ["POST", "PUT", "DELETE"]:
                    routes.append(
                        {
                            "match": {
                                "prefix": "/",
                                "headers": [{"name": ":method", "string_match": {"exact": method}}],
                            },
                            "direct_response": {
                                "status": 403,
                                "body": {"inline_string": f"{method} not allowed for this domain"},
                            },
                        }
                    )

            if allowed_paths:
                # Per-path routes (allow specific paths only)
                for path_pattern in allowed_paths:
                    route_entry = self._build_route_entry(
                        path_pattern,
                        cluster_name,
                        timeout,
                        actual_domain,
                        domain_rl,
                        default_rpm,
                        default_burst,
                    )
                    routes.append(route_entry)
                # Catch-all deny for this domain
                routes.append(
                    {
                        "match": {"prefix": "/"},
                        "direct_response": {
                            "status": 403,
                            "body": {
                                "inline_string": '{"error": "path_not_allowed", "message": "This path is not in the allowlist for this domain"}'
                            },
                        },
                    }
                )
            else:
                # Main route (all paths allowed)
                route = {
                    "match": {"prefix": "/"},
                    "route": {
                        "cluster": cluster_name,
                        "timeout": timeout,
                    },
                    "request_headers_to_add": [
                        {
                            "header": {"key": "X-Real-Domain", "value": actual_domain},
                            "append_action": "OVERWRITE_IF_EXISTS_OR_ADD",
                        },
                    ],
                }
                # Per-route rate limit override if domain has custom rate limit
                if domain_rl:
                    route["typed_per_filter_config"] = {
                        "envoy.filters.http.local_ratelimit": self._build_per_route_ratelimit(
                            cluster_name,
                            domain_rl,
                            default_rpm,
                            default_burst,
                        )
                    }
                routes.append(route)

            # Add virtual host for real domain
            virtual_hosts.append({"name": cluster_name, "domains": domain_patterns, "routes": routes})

            # Add virtual host for devbox.local alias if present
            if alias:
                alias_domains = [
                    f"{alias}.devbox.local",
                    f"{alias}.devbox.local:*",
                ]
                alias_route = {
                    "match": {"prefix": "/"},
                    "route": {"cluster": cluster_name, "timeout": timeout, "auto_host_rewrite": True},
                    "request_headers_to_add": [
                        {
                            "header": {"key": "X-Real-Domain", "value": actual_domain},
                            "append_action": "OVERWRITE_IF_EXISTS_OR_ADD",
                        },
                    ],
                }
                # Per-route rate limit for alias too
                if domain_rl:
                    alias_route["typed_per_filter_config"] = {
                        "envoy.filters.http.local_ratelimit": self._build_per_route_ratelimit(
                            cluster_name,
                            domain_rl,
                            default_rpm,
                            default_burst,
                        )
                    }
                virtual_hosts.append({"name": f"devbox_{alias}", "domains": alias_domains, "routes": [alias_route]})

            # Generate cluster if not already added
            if cluster_name not in cluster_names:
                cluster_names.add(cluster_name)

                # Determine actual host for cluster
                actual_host = domain
                if domain.startswith("*."):
                    actual_host = domain[2:]  # Remove wildcard prefix

                # tls defaults to True (HTTPS upstream); set tls: false for HTTP upstreams
                use_tls = entry.get("tls", True)

                clusters.append(self._generate_cluster(cluster_name, actual_host, tls=use_tls))

        # Add email proxy route if email accounts are configured
        email_vhost, email_cluster = self._generate_email_envoy_config()
        if email_vhost:
            virtual_hosts.append(email_vhost)
            clusters.append(email_cluster)

        # Add catch-all block
        virtual_hosts.append(
            {
                "name": "blocked",
                "domains": ["*"],
                "routes": [
                    {
                        "match": {"prefix": "/"},
                        "direct_response": {
                            "status": 403,
                            "body": {
                                "inline_string": '{"error": "destination_not_allowed", "message": "This domain is not in the allowlist"}'
                            },
                        },
                    }
                ],
            }
        )

        # Build full Envoy config
        config = self._build_envoy_config(
            virtual_hosts,
            clusters,
            default_rate_limit,
            credential_headers,
        )
        return config

    def _build_route_entry(
        self,
        path_pattern: str,
        cluster_name: str,
        timeout: str,
        actual_domain: str,
        domain_rl: dict,
        default_rpm: int,
        default_burst: int,
    ) -> dict:
        """Build a single route entry for an allowed path pattern."""
        # Determine match type from pattern
        if path_pattern.endswith("*"):
            # Prefix match: /api/* or /api*
            prefix = path_pattern.rstrip("*")
            match = {"prefix": prefix}
        else:
            # Exact match
            match = {"path": path_pattern}

        route = {
            "match": match,
            "route": {
                "cluster": cluster_name,
                "timeout": timeout,
            },
            "request_headers_to_add": [
                {
                    "header": {"key": "X-Real-Domain", "value": actual_domain},
                    "append_action": "OVERWRITE_IF_EXISTS_OR_ADD",
                },
            ],
        }

        if domain_rl:
            route["typed_per_filter_config"] = {
                "envoy.filters.http.local_ratelimit": self._build_per_route_ratelimit(
                    cluster_name,
                    domain_rl,
                    default_rpm,
                    default_burst,
                )
            }

        return route

    def _build_per_route_ratelimit(
        self, cluster_name: str, domain_rl: dict, default_rpm: int, default_burst: int
    ) -> dict:
        """Build per-route local_ratelimit typed_per_filter_config."""
        rpm = domain_rl.get("requests_per_minute", default_rpm)
        burst = domain_rl.get("burst_size", default_burst)
        return {
            "@type": "type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit",
            "stat_prefix": f"{cluster_name}_rl",
            "token_bucket": self._rpm_to_token_bucket(rpm, burst),
            "filter_enabled": {"default_value": {"numerator": 100, "denominator": "HUNDRED"}},
            "filter_enforced": {"default_value": {"numerator": 100, "denominator": "HUNDRED"}},
            "status": {"code": "TooManyRequests"},
        }

    def _generate_email_envoy_config(self) -> tuple:
        """Generate Envoy virtual host + cluster for email proxy if email accounts exist."""
        email_accounts = self.get_email_accounts()
        if not email_accounts:
            return None, None

        virtual_host = {
            "name": "devbox_email",
            "domains": ["email.devbox.local", "email.devbox.local:*"],
            "routes": [
                {
                    "match": {"prefix": "/"},
                    "route": {
                        "cluster": "email_proxy",
                        "timeout": "60s",
                    },
                }
            ],
        }

        cluster = {
            "name": "email_proxy",
            "type": "STRICT_DNS",
            "connect_timeout": "5s",
            "lb_policy": "ROUND_ROBIN",
            "load_assignment": {
                "cluster_name": "email_proxy",
                "endpoints": [
                    {
                        "lb_endpoints": [
                            {
                                "endpoint": {
                                    "address": {"socket_address": {"address": "10.200.2.40", "port_value": 8025}}
                                }
                            }
                        ]
                    }
                ],
            },
        }

        return virtual_host, cluster

    def _domain_to_cluster_name(self, domain: str) -> str:
        """Convert domain to valid cluster name."""
        name = domain.replace(".", "_").replace("*", "wildcard").replace("-", "_")
        return name

    def _generate_cluster(self, name: str, host: str, port: int = 443, tls: bool = True) -> dict:
        """Generate Envoy cluster config."""
        cb = self.get_circuit_breaker_defaults()
        cluster = {
            "name": name,
            "type": "LOGICAL_DNS",
            "connect_timeout": "10s",
            "lb_policy": "ROUND_ROBIN",
            "circuit_breakers": {
                "thresholds": [
                    {
                        "priority": "DEFAULT",
                        "max_connections": cb.get("max_connections", 1000),
                        "max_pending_requests": cb.get("max_pending_requests", 1000),
                        "max_requests": cb.get("max_requests", 1000),
                        "max_retries": cb.get("max_retries", 3),
                    }
                ]
            },
            "load_assignment": {
                "cluster_name": name,
                "endpoints": [
                    {
                        "lb_endpoints": [
                            {"endpoint": {"address": {"socket_address": {"address": host, "port_value": port}}}}
                        ]
                    }
                ],
            },
        }
        if tls:
            cluster["transport_socket"] = {
                "name": "envoy.transport_sockets.tls",
                "typed_config": {
                    "@type": "type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
                    "sni": host,
                    "common_tls_context": {
                        "validation_context": {"trusted_ca": {"filename": "/etc/ssl/certs/ca-certificates.crt"}}
                    },
                },
            }
        return cluster

    def _build_envoy_config(
        self, virtual_hosts: list, clusters: list, default_rate_limit: dict, credential_headers: set
    ) -> dict:
        """Build complete Envoy config."""
        return {
            "admin": {"address": {"socket_address": {"address": "127.0.0.1", "port_value": 9901}}},
            "static_resources": {
                "listeners": [
                    self._build_https_listener(
                        virtual_hosts,
                        default_rate_limit,
                        credential_headers,
                    )
                ],
                "clusters": [self._build_control_plane_cluster(), *clusters],
            },
            "layered_runtime": {
                "layers": [
                    {
                        "name": "static_layer",
                        "static_layer": {
                            "envoy": {"resource_limits": {"listener": {"egress_https": {"connection_limit": 1000}}}}
                        },
                    }
                ]
            },
        }

    def _build_control_plane_cluster(self) -> dict:
        """Build cluster for the warden API.

        Points to warden on infra-net (Docker DNS) so the ext_authz filter
        can reach the credential injection endpoint.
        """
        return {
            "name": "control_plane_api",
            "type": "STRICT_DNS",
            "connect_timeout": "5s",
            "lb_policy": "ROUND_ROBIN",
            "load_assignment": {
                "cluster_name": "control_plane_api",
                "endpoints": [
                    {
                        "lb_endpoints": [
                            {"endpoint": {"address": {"socket_address": {"address": "warden", "port_value": 8080}}}}
                        ]
                    }
                ],
            },
        }

    def _build_https_listener(self, virtual_hosts: list, default_rate_limit: dict, credential_headers: set) -> dict:
        """Build HTTPS egress listener."""
        return {
            "name": "egress_https",
            "address": {"socket_address": {"address": "0.0.0.0", "port_value": 8443}},
            "filter_chains": [
                {
                    "filters": [
                        {
                            "name": "envoy.filters.network.http_connection_manager",
                            "typed_config": {
                                "@type": "type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager",
                                "stat_prefix": "egress_https",
                                "codec_type": "AUTO",
                                "access_log": [self._build_access_log()],
                                "route_config": {"name": "egress_routes", "virtual_hosts": virtual_hosts},
                                "http_filters": [
                                    self._build_ext_authz_filter(credential_headers),
                                    self._build_local_ratelimit_filter(default_rate_limit),
                                    {
                                        "name": "envoy.filters.http.router",
                                        "typed_config": {
                                            "@type": "type.googleapis.com/envoy.extensions.filters.http.router.v3.Router"
                                        },
                                    },
                                ],
                            },
                        }
                    ]
                }
            ],
        }

    def _build_access_log(self) -> dict:
        """Build access log config."""
        return {
            "name": "envoy.access_loggers.stdout",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog",
                "log_format": {
                    "json_format": {
                        "timestamp": "%START_TIME%",
                        "authority": "%REQ(:AUTHORITY)%",
                        "path": "%REQ(:PATH)%",
                        "method": "%REQ(:METHOD)%",
                        "response_code": "%RESPONSE_CODE%",
                        "response_flags": "%RESPONSE_FLAGS%",
                        "duration_ms": "%DURATION%",
                        "bytes_received": "%BYTES_RECEIVED%",
                        "bytes_sent": "%BYTES_SENT%",
                        "upstream_cluster": "%UPSTREAM_CLUSTER%",
                        "user_agent": "%REQ(USER-AGENT)%",
                        "credential_injected": "%REQ(X-CREDENTIAL-INJECTED)%",
                        "rate_limited": "%REQ(X-RATE-LIMITED)%",
                    }
                },
            },
        }

    def _build_ext_authz_filter(self, credential_headers: set) -> dict:
        """Build ext_authz HTTP service filter for credential injection via warden."""
        # Build allowed upstream header patterns from credential headers
        upstream_patterns = [
            {"exact": "x-credential-injected"},  # tracking header
        ]
        for header in sorted(credential_headers):
            upstream_patterns.append({"exact": header})

        return {
            "name": "envoy.filters.http.ext_authz",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.ext_authz.v3.ExtAuthz",
                "transport_api_version": "V3",
                "allowed_headers": {
                    "patterns": [
                        {"exact": ":authority"},
                        {"exact": ":method"},
                        {"exact": ":path"},
                    ]
                },
                "http_service": {
                    "server_uri": {
                        "uri": "warden:8080",
                        "cluster": "control_plane_api",
                        "timeout": "5s",
                    },
                    "path_prefix": "/api/v1/ext-authz",
                    "authorization_response": {"allowed_upstream_headers": {"patterns": upstream_patterns}},
                },
                "failure_mode_allow": True,
            },
        }

    def _build_local_ratelimit_filter(self, default_rate_limit: dict) -> dict:
        """Build global local_ratelimit filter with default rate limit."""
        rpm = default_rate_limit.get("requests_per_minute", 120)
        burst = default_rate_limit.get("burst_size", 20)

        return {
            "name": "envoy.filters.http.local_ratelimit",
            "typed_config": {
                "@type": "type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit",
                "stat_prefix": "local_rate_limiter",
                "token_bucket": self._rpm_to_token_bucket(rpm, burst),
                "filter_enabled": {"default_value": {"numerator": 100, "denominator": "HUNDRED"}},
                "filter_enforced": {"default_value": {"numerator": 100, "denominator": "HUNDRED"}},
                "status": {"code": "TooManyRequests"},
                "response_headers_to_add": [
                    {
                        "header": {"key": "x-rate-limited", "value": "true"},
                        "append_action": "OVERWRITE_IF_EXISTS_OR_ADD",
                    }
                ],
            },
        }

    @staticmethod
    def _rpm_to_token_bucket(rpm: int, burst: int) -> dict:
        """Convert requests_per_minute + burst_size to Envoy token bucket config."""
        if rpm >= 60:
            tokens_per_fill = rpm // 60
            fill_interval = "1s"
        else:
            tokens_per_fill = 1
            fill_interval = f"{60 // rpm}s"

        return {
            "max_tokens": burst,
            "tokens_per_fill": tokens_per_fill,
            "fill_interval": fill_interval,
        }

    # =========================================================================
    # Output Methods
    # =========================================================================

    def write_corefile(self, output_path: str) -> bool:
        """Write generated Corefile."""
        try:
            content = self.generate_corefile()
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            Path(output_path).write_text(content)
            logger.info(f"Wrote CoreDNS config to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to write Corefile: {e}")
            return False

    def write_envoy_config(self, output_path: str) -> bool:
        """Write generated Envoy config."""
        try:
            config = self.generate_envoy_config()
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)

            # Write as YAML for readability
            yaml_content = yaml.dump(config, default_flow_style=False, sort_keys=False)

            # Add header
            header = f"""# =============================================================================
# Envoy Configuration - Auto-generated from cagent.yaml
# Generated: {datetime.utcnow().isoformat()}Z
# DO NOT EDIT - changes will be overwritten
# =============================================================================

"""
            Path(output_path).write_text(header + yaml_content)
            logger.info(f"Wrote Envoy config to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to write Envoy config: {e}")
            return False

    def write_resource_env(self, env_path: str) -> bool:
        """Write resource limits from cagent.yaml to .env file.

        Merges CELL_CPU_LIMIT, CELL_MEMORY_LIMIT, CELL_PIDS_LIMIT into the
        existing .env file (preserves other variables).  If resources section
        is absent or null in cagent.yaml, does nothing.
        """
        resources = self.get_resources()
        if not resources:
            return True  # Nothing to write

        env_vars = {}
        if resources.get("cpu_limit") is not None:
            env_vars["CELL_CPU_LIMIT"] = str(resources["cpu_limit"])
        if resources.get("memory_limit_mb") is not None:
            mb = int(resources["memory_limit_mb"])
            # Convert MB to Docker format (e.g., 4096 -> 4G, 512 -> 512M)
            if mb >= 1024 and mb % 1024 == 0:
                env_vars["CELL_MEMORY_LIMIT"] = f"{mb // 1024}G"
            else:
                env_vars["CELL_MEMORY_LIMIT"] = f"{mb}M"
        if resources.get("pids_limit") is not None:
            env_vars["CELL_PIDS_LIMIT"] = str(int(resources["pids_limit"]))

        if not env_vars:
            return True

        try:
            env_file = Path(env_path)
            existing_lines = []
            existing_keys = set()

            if env_file.exists():
                for line in env_file.read_text().splitlines():
                    key = line.split("=", 1)[0].strip() if "=" in line else ""
                    if key in env_vars:
                        existing_keys.add(key)
                        existing_lines.append(f"{key}={env_vars[key]}")
                    else:
                        existing_lines.append(line)

            # Append any new keys not already in the file
            for key, value in env_vars.items():
                if key not in existing_keys:
                    existing_lines.append(f"{key}={value}")

            env_file.write_text("\n".join(existing_lines) + "\n")
            logger.info(f"Wrote resource limits to {env_path}: {env_vars}")
            return True
        except Exception as e:
            logger.error(f"Failed to write resource env: {e}")
            return False

    def generate_all(self, coredns_path: str, envoy_path: str) -> bool:
        """Generate all configs."""
        success = True
        success = self.write_corefile(coredns_path) and success
        success = self.write_envoy_config(envoy_path) and success
        return success


def main():
    """CLI entrypoint."""
    import argparse

    parser = argparse.ArgumentParser(description="Generate configs from cagent.yaml")
    parser.add_argument("--config", default="/etc/cagent/cagent.yaml", help="Path to cagent.yaml")
    parser.add_argument("--coredns", default="/etc/coredns/Corefile", help="Output path for Corefile")
    parser.add_argument("--envoy", default="/etc/envoy/envoy.yaml", help="Output path for Envoy config")
    parser.add_argument("--watch", action="store_true", help="Watch for config changes")

    args = parser.parse_args()

    generator = ConfigGenerator(args.config)

    if args.watch:
        import time

        logger.info(f"Watching {args.config} for changes...")
        while True:
            if generator.load_config():
                generator.generate_all(args.coredns, args.envoy)
            time.sleep(5)
    else:
        if generator.load_config():
            generator.generate_all(args.coredns, args.envoy)


if __name__ == "__main__":
    main()
