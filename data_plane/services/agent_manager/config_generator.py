"""
Config Generator - Generates CoreDNS and Envoy configs from cagent.yaml

Single source of truth: configs/cagent.yaml
Outputs:
  - configs/coredns/Corefile.generated
  - configs/envoy/envoy.generated.yaml
"""

import os
import yaml
import json
import hashlib
import logging
from pathlib import Path
from datetime import datetime
from typing import Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


class ConfigGenerator:
    def __init__(self, config_path: str = "/etc/cagent/cagent.yaml"):
        self.config_path = Path(config_path)
        self.config = {}
        self.last_hash = None

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
        """Get list of domain configs."""
        return self.config.get('domains', [])

    def get_internal_services(self) -> list:
        """Get list of internal service names."""
        return self.config.get('internal_services', [])

    def get_email_accounts(self) -> list:
        """Get list of email account configs."""
        return self.config.get('email', {}).get('accounts', [])

    def get_dns_config(self) -> dict:
        """Get DNS configuration."""
        return self.config.get('dns', {
            'upstream': ['8.8.8.8', '8.8.4.4'],
            'cache_ttl': 300
        })

    def get_default_rate_limit(self) -> dict:
        """Get default rate limit config."""
        return self.config.get('rate_limits', {}).get('default', {
            'requests_per_minute': 120,
            'burst_size': 20
        })

    def get_circuit_breaker_defaults(self) -> dict:
        """Get default circuit breaker config."""
        return self.config.get('circuit_breakers', {
            'max_connections': 1000,
            'max_pending_requests': 1000,
            'max_requests': 1000,
            'max_retries': 3,
        })

    # =========================================================================
    # CoreDNS Generation
    # =========================================================================

    def generate_corefile(self) -> str:
        """Generate CoreDNS Corefile from config."""
        dns_config = self.get_dns_config()
        upstream = ' '.join(dns_config.get('upstream', ['8.8.8.8', '8.8.4.4']))
        cache_ttl = dns_config.get('cache_ttl', 300)

        lines = [
            "# =============================================================================",
            "# CoreDNS Configuration - Auto-generated from cagent.yaml",
            f"# Generated: {datetime.utcnow().isoformat()}Z",
            "# DO NOT EDIT - changes will be overwritten",
            "# =============================================================================",
            "",
            "# Devbox.local aliases -> Envoy proxy (10.200.1.10)",
            "devbox.local {",
            '    template IN A {',
            '        answer "{{ .Name }} 60 IN A 10.200.1.10"',
            '    }',
            '    template IN AAAA {',
            '        rcode NOERROR',
            '    }',
            '    log',
            '}',
            "",
        ]

        # Collect unique domains (expand wildcards for CoreDNS)
        domains = set()
        for entry in self.get_domains():
            domain = entry.get('domain', '')
            if domain.startswith('*.'):
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
            lines.extend([
                f"{domain} {{",
                f"    forward . {upstream}",
                f"    cache {cache_ttl}",
                "    log",
                "}",
                "",
            ])

        # Internal services (Docker DNS)
        lines.append("# Internal services (Docker DNS)")
        for service in self.get_internal_services():
            lines.extend([
                f"{service} {{",
                "    forward . 127.0.0.11",
                "    log",
                "}",
                "",
            ])

        # Email proxy internal DNS (if email accounts configured)
        if self.get_email_accounts():
            lines.extend([
                "email-proxy {",
                "    forward . 127.0.0.11",
                "    log",
                "}",
                "",
            ])

        # Catch-all block (single . {} block: health, metrics, logging, and NXDOMAIN)
        lines.extend([
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
        ])

        return '\n'.join(lines)

    # =========================================================================
    # Envoy Generation
    # =========================================================================

    def generate_envoy_config(self) -> dict:
        """Generate Envoy config from cagent.yaml."""
        domains = self.get_domains()
        default_rate_limit = self.get_default_rate_limit()

        # Build virtual hosts and clusters
        virtual_hosts = []
        clusters = []
        cluster_names = set()

        for entry in domains:
            domain = entry.get('domain', '')
            if not domain:
                continue

            alias = entry.get('alias')
            timeout = entry.get('timeout', '30s')
            read_only = entry.get('read_only', False)

            # Generate cluster name from domain
            cluster_name = self._domain_to_cluster_name(domain)

            # Domain patterns for virtual host
            domain_patterns = [domain, f"{domain}:443"]
            if domain.startswith('*.'):
                # Keep wildcard as-is for Envoy
                pass

            # Build routes
            routes = []

            if read_only:
                # Block POST/PUT/DELETE
                for method in ['POST', 'PUT', 'DELETE']:
                    routes.append({
                        'match': {
                            'prefix': '/',
                            'headers': [{'name': ':method', 'string_match': {'exact': method}}]
                        },
                        'direct_response': {
                            'status': 403,
                            'body': {'inline_string': f'{method} not allowed for this domain'}
                        }
                    })

            # Main route
            routes.append({
                'match': {'prefix': '/'},
                'route': {
                    'cluster': cluster_name,
                    'timeout': timeout,
                }
            })

            # Add virtual host for real domain
            virtual_hosts.append({
                'name': cluster_name,
                'domains': domain_patterns,
                'routes': routes
            })

            # Add virtual host for devbox.local alias if present
            if alias:
                alias_domains = [
                    f"{alias}.devbox.local",
                    f"{alias}.devbox.local:*",
                ]
                alias_routes = [{
                    'match': {'prefix': '/'},
                    'route': {
                        'cluster': cluster_name,
                        'timeout': timeout,
                        'auto_host_rewrite': True
                    }
                }]
                virtual_hosts.append({
                    'name': f"devbox_{alias}",
                    'domains': alias_domains,
                    'routes': alias_routes
                })

            # Generate cluster if not already added
            if cluster_name not in cluster_names:
                cluster_names.add(cluster_name)

                # Determine actual host for cluster
                actual_host = domain
                if domain.startswith('*.'):
                    actual_host = domain[2:]  # Remove wildcard prefix

                clusters.append(self._generate_cluster(cluster_name, actual_host))

        # Add email proxy route if email accounts are configured
        email_vhost, email_cluster = self._generate_email_envoy_config()
        if email_vhost:
            virtual_hosts.append(email_vhost)
            clusters.append(email_cluster)

        # Add catch-all block
        virtual_hosts.append({
            'name': 'blocked',
            'domains': ['*'],
            'routes': [{
                'match': {'prefix': '/'},
                'direct_response': {
                    'status': 403,
                    'body': {'inline_string': '{"error": "destination_not_allowed", "message": "This domain is not in the allowlist"}'}
                }
            }]
        })

        # Build full Envoy config
        config = self._build_envoy_config(virtual_hosts, clusters, default_rate_limit)
        return config

    def _generate_email_envoy_config(self) -> tuple:
        """Generate Envoy virtual host + cluster for email proxy if email accounts exist."""
        email_accounts = self.get_email_accounts()
        if not email_accounts:
            return None, None

        virtual_host = {
            'name': 'devbox_email',
            'domains': ['email.devbox.local', 'email.devbox.local:*'],
            'routes': [{
                'match': {'prefix': '/'},
                'route': {
                    'cluster': 'email_proxy',
                    'timeout': '60s',
                }
            }]
        }

        cluster = {
            'name': 'email_proxy',
            'type': 'STRICT_DNS',
            'connect_timeout': '5s',
            'lb_policy': 'ROUND_ROBIN',
            'load_assignment': {
                'cluster_name': 'email_proxy',
                'endpoints': [{
                    'lb_endpoints': [{
                        'endpoint': {
                            'address': {
                                'socket_address': {
                                    'address': '10.200.2.40',
                                    'port_value': 8025
                                }
                            }
                        }
                    }]
                }]
            }
        }

        return virtual_host, cluster

    def _domain_to_cluster_name(self, domain: str) -> str:
        """Convert domain to valid cluster name."""
        name = domain.replace('.', '_').replace('*', 'wildcard').replace('-', '_')
        return name

    def _generate_cluster(self, name: str, host: str, port: int = 443) -> dict:
        """Generate Envoy cluster config."""
        cb = self.get_circuit_breaker_defaults()
        return {
            'name': name,
            'type': 'LOGICAL_DNS',
            'connect_timeout': '10s',
            'lb_policy': 'ROUND_ROBIN',
            'circuit_breakers': {
                'thresholds': [{
                    'priority': 'DEFAULT',
                    'max_connections': cb.get('max_connections', 1000),
                    'max_pending_requests': cb.get('max_pending_requests', 1000),
                    'max_requests': cb.get('max_requests', 1000),
                    'max_retries': cb.get('max_retries', 3),
                }]
            },
            'load_assignment': {
                'cluster_name': name,
                'endpoints': [{
                    'lb_endpoints': [{
                        'endpoint': {
                            'address': {
                                'socket_address': {
                                    'address': host,
                                    'port_value': port
                                }
                            }
                        }
                    }]
                }]
            },
            'transport_socket': {
                'name': 'envoy.transport_sockets.tls',
                'typed_config': {
                    '@type': 'type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext',
                    'sni': host
                }
            }
        }

    def _build_envoy_config(self, virtual_hosts: list, clusters: list, default_rate_limit: dict) -> dict:
        """Build complete Envoy config."""
        return {
            'admin': {
                'address': {
                    'socket_address': {'address': '127.0.0.1', 'port_value': 9901}
                }
            },
            'static_resources': {
                'listeners': [
                    self._build_https_listener(virtual_hosts, default_rate_limit)
                ],
                'clusters': [
                    self._build_control_plane_cluster(),
                    *clusters
                ]
            },
            'layered_runtime': {
                'layers': [{
                    'name': 'static_layer',
                    'static_layer': {
                        'envoy': {
                            'resource_limits': {
                                'listener': {
                                    'egress_https': {
                                        'connection_limit': 1000
                                    }
                                }
                            }
                        }
                    }
                }]
            }
        }

    def _build_control_plane_cluster(self) -> dict:
        """Build cluster for control plane API.

        Derives address and port from CONTROL_PLANE_URL (same env var used
        by the agent-manager) so Envoy's Lua httpCall reaches the backend
        via container-to-container networking.
        """
        cp_url = os.environ.get("CONTROL_PLANE_URL", "") or "http://backend:8000"
        # Strip scheme
        host_port = cp_url.split("://", 1)[-1]
        if ":" in host_port:
            address, port_str = host_port.rsplit(":", 1)
            port = int(port_str)
        else:
            address = host_port
            port = 8000

        return {
            'name': 'control_plane_api',
            'type': 'STRICT_DNS',
            'connect_timeout': '5s',
            'lb_policy': 'ROUND_ROBIN',
            'load_assignment': {
                'cluster_name': 'control_plane_api',
                'endpoints': [{
                    'lb_endpoints': [{
                        'endpoint': {
                            'address': {
                                'socket_address': {
                                    'address': address,
                                    'port_value': port
                                }
                            }
                        }
                    }]
                }]
            }
        }

    def _build_https_listener(self, virtual_hosts: list, default_rate_limit: dict) -> dict:
        """Build HTTPS egress listener."""
        return {
            'name': 'egress_https',
            'address': {
                'socket_address': {'address': '0.0.0.0', 'port_value': 8443}
            },
            'filter_chains': [{
                'filters': [{
                    'name': 'envoy.filters.network.http_connection_manager',
                    'typed_config': {
                        '@type': 'type.googleapis.com/envoy.extensions.filters.network.http_connection_manager.v3.HttpConnectionManager',
                        'stat_prefix': 'egress_https',
                        'codec_type': 'AUTO',
                        'access_log': [self._build_access_log()],
                        'route_config': {
                            'name': 'egress_routes',
                            'virtual_hosts': virtual_hosts
                        },
                        'http_filters': [
                            self._build_lua_filter(default_rate_limit),
                            {'name': 'envoy.filters.http.router', 'typed_config': {
                                '@type': 'type.googleapis.com/envoy.extensions.filters.http.router.v3.Router'
                            }}
                        ]
                    }
                }]
            }]
        }

    def _build_access_log(self) -> dict:
        """Build access log config."""
        return {
            'name': 'envoy.access_loggers.stdout',
            'typed_config': {
                '@type': 'type.googleapis.com/envoy.extensions.access_loggers.stream.v3.StdoutAccessLog',
                'log_format': {
                    'json_format': {
                        'timestamp': '%START_TIME%',
                        'authority': '%REQ(:AUTHORITY)%',
                        'path': '%REQ(:PATH)%',
                        'method': '%REQ(:METHOD)%',
                        'response_code': '%RESPONSE_CODE%',
                        'response_flags': '%RESPONSE_FLAGS%',
                        'duration_ms': '%DURATION%',
                        'bytes_received': '%BYTES_RECEIVED%',
                        'bytes_sent': '%BYTES_SENT%',
                        'upstream_cluster': '%UPSTREAM_CLUSTER%',
                        'user_agent': '%REQ(USER-AGENT)%',
                        'credential_injected': '%REQ(X-CREDENTIAL-INJECTED)%',
                        'rate_limited': '%REQ(X-RATE-LIMITED)%'
                    }
                }
            }
        }

    def _build_lua_filter(self, default_rate_limit: dict) -> dict:
        """Build Lua filter referencing external filter.lua file."""
        return {
            'name': 'envoy.filters.http.lua',
            'typed_config': {
                '@type': 'type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua',
                'default_source_code': {
                    'filename': '/etc/envoy/filter.lua'
                }
            }
        }

    def _escape_lua_string(self, s: str) -> str:
        """Escape a string for safe inclusion in a Lua string literal.

        Prevents Lua injection by escaping backslashes, double quotes,
        and control characters.
        """
        s = s.replace('\\', '\\\\')
        s = s.replace('"', '\\"')
        s = s.replace('\n', '\\n')
        s = s.replace('\r', '\\r')
        s = s.replace('\0', '')
        return s

    def generate_lua_filter(self) -> str:
        """Generate Lua filter code from cagent.yaml config.

        Builds a standalone Lua file with static config tables baked in
        and the full filter logic (matching, rate limiting, credential
        injection, DNS tunneling detection, egress tracking).
        """
        default_rate_limit = self.get_default_rate_limit()

        # Build credential map from config
        credentials = {}
        rate_limits = {}
        alias_map = {}

        for entry in self.get_domains():
            domain = entry.get('domain', '')
            alias = entry.get('alias')
            cred = entry.get('credential')
            rl = entry.get('rate_limit')

            if cred:
                env_var = cred.get('env', '')
                value = os.environ.get(env_var, '') if env_var else ''
                if value:
                    header_format = cred.get('format', '{value}')
                    credentials[domain] = {
                        'header_name': cred.get('header', 'Authorization'),
                        'header_value': header_format.replace('{value}', value)
                    }

            if rl:
                rate_limits[domain] = rl

            if alias:
                alias_map[f"{alias}.devbox.local"] = domain

        # Build Lua table literals with proper escaping
        creds_lua = self._lua_table(credentials)
        rate_limits_lua = self._lua_table(rate_limits)
        alias_map_lua = self._lua_table(alias_map)
        default_rpm = int(default_rate_limit.get('requests_per_minute', 120))
        default_burst = int(default_rate_limit.get('burst_size', 20))

        lines = [
            '-- =======================================================================',
            '-- Auto-generated Lua filter from cagent.yaml',
            f'-- Generated: {datetime.utcnow().isoformat()}Z',
            '-- DO NOT EDIT - changes will be overwritten by agent-manager',
            '-- =======================================================================',
            '',
            '-- Configuration',
            'local DATAPLANE_MODE = os.getenv("DATAPLANE_MODE") or "standalone"',
            'local API_TOKEN = os.getenv("CONTROL_PLANE_TOKEN") or ""',
            'local CACHE_TTL_SECONDS = 300',
            'local CP_FAILURE_BACKOFF = 30',
            'local DEFAULT_EGRESS_LIMIT = 100 * 1024 * 1024  -- 100MB default',
            'local EGRESS_WINDOW_SECONDS = 3600',
            '',
            '-- Caches',
            'local domain_policy_cache = {}',
            'local token_buckets = {}',
            'local egress_bytes = {}',
            'local cp_available = true',
            'local cp_last_failure = 0',
            '',
            '-- Static config from cagent.yaml',
            f'local static_credentials = {creds_lua}',
            f'local static_rate_limits = {rate_limits_lua}',
            f'local alias_map = {alias_map_lua}',
            '',
            f'local default_rate_limit = {{requests_per_minute = {default_rpm}, burst_size = {default_burst}}}',
            '',
            '-- =======================================================================',
            '-- Utility Functions',
            '-- =======================================================================',
            '',
            'function clean_host(host)',
            '  return string.match(host, "^([^:]+)") or host',
            'end',
            '',
            'function is_devbox_local(host)',
            '  local host_clean = clean_host(host)',
            '  return string.match(host_clean, "%.devbox%.local$") ~= nil',
            'end',
            '',
            'function get_real_domain(host)',
            '  local host_clean = clean_host(host)',
            '  return alias_map[host_clean] or host_clean',
            'end',
            '',
            'function url_encode(str)',
            '  if str then',
            '    str = string.gsub(str, "([^%w%-%.%_%~])", function(c)',
            '      return string.format("%%%02X", string.byte(c))',
            '    end)',
            '  end',
            '  return str',
            'end',
            '',
            'function detect_dns_tunneling(host)',
            '  local parts = {}',
            '  for part in string.gmatch(host, "[^%.]+") do',
            '    table.insert(parts, part)',
            '  end',
            '  for _, part in ipairs(parts) do',
            '    if string.len(part) > 63 then',
            '      return true, "Subdomain exceeds 63 characters"',
            '    end',
            '  end',
            '  if string.len(host) > 100 then',
            '    return true, "Hostname unusually long"',
            '  end',
            '  if #parts > 6 then',
            '    return true, "Excessive subdomain depth"',
            '  end',
            '  local suspicious_labels = 0',
            '  for _, part in ipairs(parts) do',
            '    if string.len(part) > 20 and string.match(part, "^[%x%-]+$") then',
            '      suspicious_labels = suspicious_labels + 1',
            '    end',
            '  end',
            '  if suspicious_labels >= 2 then',
            '    return true, "Multiple hex-encoded subdomain labels"',
            '  end',
            '  return false, nil',
            'end',
            '',
            'function should_contact_cp()',
            '  if DATAPLANE_MODE == "standalone" then return false end',
            '  if API_TOKEN == "" then return false end',
            '  if not cp_available and (os.time() - cp_last_failure) < CP_FAILURE_BACKOFF then',
            '    return false',
            '  end',
            '  return true',
            'end',
            '',
            'function mark_cp_failure()',
            '  cp_available = false',
            '  cp_last_failure = os.time()',
            'end',
            '',
            'function mark_cp_success()',
            '  cp_available = true',
            'end',
            '',
            '-- =======================================================================',
            '-- Wildcard Domain Matching',
            '-- =======================================================================',
            '',
            'function match_domain_wildcard(domain, tbl)',
            '  local exact = tbl[domain]',
            '  if exact ~= nil then return exact end',
            '  for pattern, value in pairs(tbl) do',
            '    if string.sub(pattern, 1, 2) == "*." then',
            '      local suffix = string.sub(pattern, 2)',
            '      if string.sub(domain, -string.len(suffix)) == suffix then',
            '        return value',
            '      end',
            '    end',
            '  end',
            '  return nil',
            'end',
            '',
            '-- =======================================================================',
            '-- Domain Policy',
            '-- =======================================================================',
            '',
            'function get_domain_policy(request_handle, domain)',
            '  local host_clean = clean_host(domain)',
            '  local cached = domain_policy_cache[host_clean]',
            '  if cached and cached.expires_at > os.time() then',
            '    return cached.policy',
            '  end',
            '  local policy = nil',
            '  if should_contact_cp() then',
            '    local headers, body = request_handle:httpCall(',
            '      "control_plane_api",',
            '      {[":method"] = "GET",',
            '       [":path"] = "/api/v1/domain-policies/for-domain?domain=" .. url_encode(host_clean),',
            '       [":authority"] = "backend",',
            '       ["authorization"] = "Bearer " .. API_TOKEN},',
            '      "", 5000, false)',
            '    if body and string.len(body) > 0 then',
            '      mark_cp_success()',
            '      policy = parse_domain_policy_response(body)',
            '    else',
            '      mark_cp_failure()',
            '    end',
            '  end',
            '  if not policy then',
            '    policy = build_static_policy(host_clean)',
            '  elseif not policy.credential then',
            '    local static = build_static_policy(host_clean)',
            '    if static.credential then',
            '      policy.credential = static.credential',
            '      policy.target_domain = static.target_domain',
            '      policy.matched = true',
            '    end',
            '  end',
            '  domain_policy_cache[host_clean] = {policy = policy, expires_at = os.time() + CACHE_TTL_SECONDS}',
            '  return policy',
            'end',
            '',
            'function parse_domain_policy_response(body)',
            '  if not body or body == "" then return nil end',
            '  local policy = {',
            '    matched = string.match(body, \'"matched"%s*:%s*true\') ~= nil,',
            '    allowed_paths = {},',
            '    requests_per_minute = tonumber(string.match(body, \'"requests_per_minute"%s*:%s*(%d+)\')) or 120,',
            '    burst_size = tonumber(string.match(body, \'"burst_size"%s*:%s*(%d+)\')) or 20,',
            '    bytes_per_hour = tonumber(string.match(body, \'"bytes_per_hour"%s*:%s*(%d+)\')) or DEFAULT_EGRESS_LIMIT,',
            '    credential = nil, target_domain = nil',
            '  }',
            '  local paths_str = string.match(body, \'"allowed_paths"%s*:%s*%[([^%]]*)%]\')',
            '  if paths_str then',
            '    for path in string.gmatch(paths_str, \'"([^"]+)"\') do',
            '      table.insert(policy.allowed_paths, path)',
            '    end',
            '  end',
            '  local cred_header = string.match(body, \'"header_name"%s*:%s*"([^"]*)"\')',
            '  local cred_value = string.match(body, \'"header_value"%s*:%s*"([^"]*)"\')',
            '  local target = string.match(body, \'"target_domain"%s*:%s*"([^"]*)"\')',
            '  if cred_header and cred_value then',
            '    policy.credential = {header_name = cred_header, header_value = cred_value}',
            '    policy.target_domain = target',
            '  end',
            '  local alias = string.match(body, \'"alias"%s*:%s*"([^"]*)"\')',
            '  if alias then policy.alias = alias end',
            '  return policy',
            'end',
            '',
            'function build_static_policy(domain)',
            '  local policy = {',
            '    matched = false, allowed_paths = {},',
            '    requests_per_minute = 120, burst_size = 20,',
            '    bytes_per_hour = DEFAULT_EGRESS_LIMIT,',
            '    credential = nil, target_domain = nil',
            '  }',
            '  local rl = match_domain_wildcard(domain, static_rate_limits) or default_rate_limit',
            '  if rl then',
            '    policy.requests_per_minute = rl.requests_per_minute or 120',
            '    policy.burst_size = rl.burst_size or 20',
            '    policy.matched = true',
            '  end',
            '  local lookup_domain = alias_map[domain] or domain',
            '  local cred = match_domain_wildcard(lookup_domain, static_credentials)',
            '  if cred then',
            '    policy.credential = {header_name = cred.header_name, header_value = cred.header_value}',
            '    policy.target_domain = lookup_domain',
            '    policy.matched = true',
            '  end',
            '  return policy',
            'end',
            '',
            '-- =======================================================================',
            '-- Path Filtering',
            '-- =======================================================================',
            '',
            'function match_path_pattern(pattern, path)',
            '  if string.sub(pattern, -2) == "/*" then',
            '    local prefix = string.sub(pattern, 1, -2)',
            '    return string.sub(path, 1, string.len(prefix)) == prefix',
            '  elseif string.sub(pattern, -1) == "*" then',
            '    local prefix = string.sub(pattern, 1, -2)',
            '    return string.sub(path, 1, string.len(prefix)) == prefix',
            '  else',
            '    return path == pattern',
            '  end',
            'end',
            '',
            'function is_path_allowed(policy, path)',
            '  if not policy.allowed_paths or #policy.allowed_paths == 0 then',
            '    return true, "no_restrictions"',
            '  end',
            '  for _, pattern in ipairs(policy.allowed_paths) do',
            '    if match_path_pattern(pattern, path) then',
            '      return true, pattern',
            '    end',
            '  end',
            '  return false, "path_not_in_allowlist"',
            'end',
            '',
            '-- =======================================================================',
            '-- Rate Limiting & Egress',
            '-- =======================================================================',
            '',
            'function check_rate_limit_with_config(request_handle, domain, rpm, burst)',
            '  local host_clean = clean_host(domain)',
            '  local now = os.time()',
            '  local bucket = token_buckets[host_clean]',
            '  if not bucket then',
            '    bucket = {tokens = burst, last_refill = now}',
            '    token_buckets[host_clean] = bucket',
            '  end',
            '  local elapsed = now - bucket.last_refill',
            '  local new_tokens = elapsed * (rpm / 60.0)',
            '  bucket.tokens = math.min(burst, bucket.tokens + new_tokens)',
            '  bucket.last_refill = now',
            '  if bucket.tokens >= 1 then',
            '    bucket.tokens = bucket.tokens - 1',
            '    return true',
            '  end',
            '  request_handle:logWarn(string.format("Rate limit exceeded for %s (limit: %d rpm)", host_clean, rpm))',
            '  return false',
            'end',
            '',
            'function check_egress_limit_with_config(request_handle, domain, bytes_limit)',
            '  local host_clean = clean_host(domain)',
            '  local now = os.time()',
            '  local tracker = egress_bytes[host_clean]',
            '  if not tracker then',
            '    tracker = {bytes = 0, window_start = now}',
            '    egress_bytes[host_clean] = tracker',
            '  end',
            '  if (now - tracker.window_start) >= EGRESS_WINDOW_SECONDS then',
            '    tracker.bytes = 0',
            '    tracker.window_start = now',
            '  end',
            '  return tracker.bytes < bytes_limit, tracker.bytes',
            'end',
            '',
            'function record_egress_bytes(response_handle, domain, bytes)',
            '  local host_clean = clean_host(domain)',
            '  local now = os.time()',
            '  local tracker = egress_bytes[host_clean]',
            '  if not tracker then',
            '    tracker = {bytes = 0, window_start = now}',
            '    egress_bytes[host_clean] = tracker',
            '  end',
            '  if (now - tracker.window_start) >= EGRESS_WINDOW_SECONDS then',
            '    tracker.bytes = 0',
            '    tracker.window_start = now',
            '  end',
            '  tracker.bytes = tracker.bytes + bytes',
            'end',
            '',
            '-- =======================================================================',
            '-- Request / Response Handlers',
            '-- =======================================================================',
            '',
            'function envoy_on_request(request_handle)',
            '  local host = request_handle:headers():get(":authority") or ""',
            '  local host_clean = clean_host(host)',
            '  local credential_injected = "false"',
            '  local rate_limited = "false"',
            '  local devbox_local = is_devbox_local(host)',
            '',
            '  if not devbox_local then',
            '    local suspicious, reason = detect_dns_tunneling(host)',
            '    if suspicious then',
            '      request_handle:logWarn("DNS tunneling blocked: " .. host .. " - " .. reason)',
            '      request_handle:respond({[":status"] = "403"}, "Blocked: suspicious hostname")',
            '      return',
            '    end',
            '  end',
            '',
            '  local policy = get_domain_policy(request_handle, host_clean)',
            '  local real_domain = host_clean',
            '  if policy and policy.target_domain then',
            '    real_domain = policy.target_domain',
            '  end',
            '',
            '  local rpm = policy and policy.requests_per_minute or 120',
            '  local burst = policy and policy.burst_size or 20',
            '  if not check_rate_limit_with_config(request_handle, real_domain, rpm, burst) then',
            '    rate_limited = "true"',
            '    request_handle:headers():add("X-Rate-Limited", rate_limited)',
            '    request_handle:respond({[":status"] = "429", ["retry-after"] = "60"},',
            '      \'{"error": "rate_limit_exceeded", "message": "Too many requests to this domain"}\')',
            '    return',
            '  end',
            '',
            '  local request_path = request_handle:headers():get(":path") or "/"',
            '  local path_only = string.match(request_path, "^([^?]+)") or request_path',
            '  local path_allowed, path_reason = is_path_allowed(policy, path_only)',
            '  if not path_allowed then',
            '    request_handle:logWarn(string.format("Path not allowed: %s%s (reason: %s)", real_domain, path_only, path_reason))',
            '    request_handle:respond({[":status"] = "403"},',
            '      \'{"error": "path_not_allowed", "message": "This path is not in the allowlist for this domain"}\')',
            '    return',
            '  end',
            '',
            '  local bytes_limit = policy and policy.bytes_per_hour or DEFAULT_EGRESS_LIMIT',
            '  local egress_allowed, current_bytes = check_egress_limit_with_config(request_handle, real_domain, bytes_limit)',
            '  if not egress_allowed then',
            '    request_handle:logWarn(string.format("Egress limit exceeded for %s: %d / %d bytes", real_domain, current_bytes, bytes_limit))',
            '    request_handle:respond({[":status"] = "429", ["retry-after"] = "3600"},',
            '      \'{"error": "egress_limit_exceeded", "message": "Hourly egress limit exceeded for this domain"}\')',
            '    return',
            '  end',
            '',
            '  request_handle:streamInfo():dynamicMetadata():set("envoy.filters.http.lua", "request_domain", real_domain)',
            '',
            '  if policy and policy.credential and policy.credential.header_name and policy.credential.header_value then',
            '    request_handle:headers():remove(policy.credential.header_name)',
            '    request_handle:headers():add(policy.credential.header_name, policy.credential.header_value)',
            '    credential_injected = "true"',
            '  end',
            '',
            '  request_handle:headers():add("X-Credential-Injected", credential_injected)',
            '  request_handle:headers():add("X-Rate-Limited", rate_limited)',
            '  request_handle:headers():add("X-Real-Domain", real_domain)',
            '  request_handle:headers():add("X-Devbox-Timestamp", os.date("!%Y-%m-%dT%H:%M:%SZ"))',
            '',
            '  if devbox_local then',
            '    request_handle:logInfo(string.format("Devbox proxy: %s -> %s (credential_injected=%s)", host, real_domain, credential_injected))',
            '  end',
            'end',
            '',
            'function envoy_on_response(response_handle)',
            '  local status = response_handle:headers():get(":status")',
            '  local content_length_str = response_handle:headers():get("content-length") or "0"',
            '  local content_length = tonumber(content_length_str) or 0',
            '  local metadata = response_handle:streamInfo():dynamicMetadata():get("envoy.filters.http.lua")',
            '  local domain = metadata and metadata["request_domain"] or nil',
            '  if domain and content_length > 0 then',
            '    record_egress_bytes(response_handle, domain, content_length)',
            '  end',
            'end',
        ]

        return '\n'.join(lines) + '\n'

    def _lua_table(self, d: dict) -> str:
        """Convert Python dict to Lua table literal with proper escaping."""
        if not d:
            return '{}'

        items = []
        for k, v in d.items():
            escaped_key = self._escape_lua_string(str(k))
            if isinstance(v, dict):
                items.append(f'["{escaped_key}"] = {self._lua_table(v)}')
            elif isinstance(v, str):
                escaped_val = self._escape_lua_string(v)
                items.append(f'["{escaped_key}"] = "{escaped_val}"')
            elif isinstance(v, bool):
                items.append(f'["{escaped_key}"] = {"true" if v else "false"}')
            elif isinstance(v, (int, float)):
                items.append(f'["{escaped_key}"] = {v}')

        return '{' + ', '.join(items) + '}'

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

    def write_lua_filter(self, output_path: str) -> bool:
        """Write generated Lua filter file."""
        try:
            content = self.generate_lua_filter()
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            Path(output_path).write_text(content)
            logger.info(f"Wrote Lua filter to {output_path}")
            return True
        except Exception as e:
            logger.error(f"Failed to write Lua filter: {e}")
            return False

    def generate_all(self, coredns_path: str, envoy_path: str, lua_path: str = None) -> bool:
        """Generate all configs."""
        success = True
        success = self.write_corefile(coredns_path) and success
        success = self.write_envoy_config(envoy_path) and success
        if lua_path:
            success = self.write_lua_filter(lua_path) and success
        return success


def main():
    """CLI entrypoint."""
    import argparse

    parser = argparse.ArgumentParser(description='Generate configs from cagent.yaml')
    parser.add_argument('--config', default='/etc/cagent/cagent.yaml', help='Path to cagent.yaml')
    parser.add_argument('--coredns', default='/etc/coredns/Corefile', help='Output path for Corefile')
    parser.add_argument('--envoy', default='/etc/envoy/envoy.yaml', help='Output path for Envoy config')
    parser.add_argument('--watch', action='store_true', help='Watch for config changes')

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


if __name__ == '__main__':
    main()
