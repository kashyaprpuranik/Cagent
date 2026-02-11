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
        return {
            'name': name,
            'type': 'LOGICAL_DNS',
            'connect_timeout': '10s',
            'lb_policy': 'ROUND_ROBIN',
            'circuit_breakers': {
                'thresholds': [{
                    'priority': 'DEFAULT',
                    'max_connections': 100,
                    'max_pending_requests': 100,
                    'max_requests': 100,
                    'max_retries': 3
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
        """Build cluster for control plane API."""
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
                                    'address': 'backend',
                                    'port_value': 8002
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
        """Build Lua filter for credential injection and rate limiting."""
        lua_code = self._generate_lua_code(default_rate_limit)
        return {
            'name': 'envoy.filters.http.lua',
            'typed_config': {
                '@type': 'type.googleapis.com/envoy.extensions.filters.http.lua.v3.Lua',
                'inline_code': lua_code
            }
        }

    def _generate_lua_code(self, default_rate_limit: dict) -> str:
        """Generate Lua code for credential injection and rate limiting."""
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

        # Generate Lua code
        return f'''
-- =======================================================================
-- Auto-generated Lua filter from cagent.yaml
-- Generated: {datetime.utcnow().isoformat()}Z
-- =======================================================================

-- Configuration
local DATAPLANE_MODE = os.getenv("DATAPLANE_MODE") or "standalone"
local API_TOKEN = os.getenv("CONTROL_PLANE_TOKEN") or ""
local CACHE_TTL_SECONDS = 300
local CP_FAILURE_BACKOFF = 30

-- Caches
local credential_cache = {{}}
local rate_limit_cache = {{}}
local token_buckets = {{}}
local cp_available = true
local cp_last_failure = 0

-- Static credentials from cagent.yaml
local static_credentials = {self._lua_table(credentials)}

-- Static rate limits from cagent.yaml
local static_rate_limits = {self._lua_table(rate_limits)}

-- Alias map: devbox.local -> real domain
local alias_map = {self._lua_table(alias_map)}

-- Default rate limit
local default_rate_limit = {{
  requests_per_minute = {default_rate_limit.get('requests_per_minute', 120)},
  burst_size = {default_rate_limit.get('burst_size', 20)}
}}

function clean_host(host)
  return string.match(host, "^([^:]+)") or host
end

function is_devbox_local(host)
  local host_clean = clean_host(host)
  return string.match(host_clean, "%.devbox%.local$") ~= nil
end

function get_real_domain(host)
  local host_clean = clean_host(host)
  return alias_map[host_clean] or host_clean
end

function detect_dns_tunneling(host)
  if string.len(host) > 100 then
    return true, "Hostname too long"
  end
  for part in string.gmatch(host, "[^%.]+") do
    if string.len(part) > 63 then
      return true, "Subdomain too long"
    end
  end
  return false, nil
end

function get_credential(domain)
  local cred = static_credentials[domain]
  if cred then return cred end
  -- Try wildcard
  for pattern, c in pairs(static_credentials) do
    if string.sub(pattern, 1, 2) == "*." then
      local suffix = string.sub(pattern, 2)
      if string.sub(domain, -string.len(suffix)) == suffix then
        return c
      end
    end
  end
  return nil
end

function get_rate_limit(domain)
  local rl = static_rate_limits[domain]
  if rl then return rl end
  -- Try wildcard
  for pattern, r in pairs(static_rate_limits) do
    if string.sub(pattern, 1, 2) == "*." then
      local suffix = string.sub(pattern, 2)
      if string.sub(domain, -string.len(suffix)) == suffix then
        return r
      end
    end
  end
  return default_rate_limit
end

function check_rate_limit(domain)
  local config = get_rate_limit(domain)
  local now = os.time()
  local bucket = token_buckets[domain]

  if not bucket then
    bucket = {{ tokens = config.burst_size, last_refill = now }}
    token_buckets[domain] = bucket
  end

  local elapsed = now - bucket.last_refill
  local tokens_per_second = config.requests_per_minute / 60.0
  local new_tokens = elapsed * tokens_per_second
  bucket.tokens = math.min(config.burst_size, bucket.tokens + new_tokens)
  bucket.last_refill = now

  if bucket.tokens >= 1 then
    bucket.tokens = bucket.tokens - 1
    return true
  end
  return false
end

function envoy_on_request(request_handle)
  local host = request_handle:headers():get(":authority") or ""
  local host_clean = clean_host(host)
  local credential_injected = "false"
  local rate_limited = "false"

  -- DNS tunneling detection
  if not is_devbox_local(host) then
    local suspicious, reason = detect_dns_tunneling(host)
    if suspicious then
      request_handle:logWarn("DNS tunneling blocked: " .. host .. " - " .. reason)
      request_handle:respond({{[":status"] = "403"}}, "Blocked: suspicious hostname")
      return
    end
  end

  -- Get real domain for devbox.local aliases
  local real_domain = get_real_domain(host_clean)

  -- Rate limiting
  if not check_rate_limit(real_domain) then
    rate_limited = "true"
    request_handle:headers():add("X-Rate-Limited", rate_limited)
    request_handle:respond(
      {{[":status"] = "429", ["retry-after"] = "60"}},
      '{{"error": "rate_limit_exceeded"}}'
    )
    return
  end

  -- Credential injection
  local cred = get_credential(real_domain)
  if cred and cred.header_name and cred.header_value then
    request_handle:headers():remove(cred.header_name)
    request_handle:headers():add(cred.header_name, cred.header_value)
    credential_injected = "true"
  end

  -- Add tracking headers
  request_handle:headers():add("X-Credential-Injected", credential_injected)
  request_handle:headers():add("X-Rate-Limited", rate_limited)
  request_handle:headers():add("X-Real-Domain", real_domain)
end

function envoy_on_response(response_handle)
  -- Response logging if needed
end
'''

    def _lua_table(self, d: dict) -> str:
        """Convert Python dict to Lua table literal."""
        if not d:
            return '{}'

        items = []
        for k, v in d.items():
            if isinstance(v, dict):
                items.append(f'["{k}"] = {self._lua_table(v)}')
            elif isinstance(v, str):
                items.append(f'["{k}"] = "{v}"')
            elif isinstance(v, (int, float)):
                items.append(f'["{k}"] = {v}')
            elif isinstance(v, bool):
                items.append(f'["{k}"] = {"true" if v else "false"}')

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

    def generate_all(self, coredns_path: str, envoy_path: str) -> bool:
        """Generate both configs."""
        success = True
        success = self.write_corefile(coredns_path) and success
        success = self.write_envoy_config(envoy_path) and success
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
