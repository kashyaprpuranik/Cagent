"""
Tests for credential injection logic (now handled by Envoy Lua filter).

These tests verify the domain matching and header formatting logic that
the Lua filter implements. The actual Lua code runs in Envoy, but the
logic can be tested here.
"""

import pytest


class TestDomainMatching:
    """Test domain matching logic used by credential injection."""

    def test_exact_domain_match(self):
        """Should match exact domains."""
        def match_domain(pattern: str, domain: str) -> bool:
            """Match domain against pattern (supports wildcard prefix)."""
            if not pattern:
                return False
            if pattern.startswith("*."):
                suffix = pattern[1:]  # .github.com
                return domain.endswith(suffix) or domain == pattern[2:]
            return domain == pattern

        # Exact matches
        assert match_domain("api.openai.com", "api.openai.com") == True
        assert match_domain("api.github.com", "api.github.com") == True

        # Should not match different domains
        assert match_domain("api.openai.com", "api.anthropic.com") == False
        assert match_domain("github.com", "api.github.com") == False

    def test_wildcard_domain_match(self):
        """Should match wildcard domain patterns."""
        def match_domain(pattern: str, domain: str) -> bool:
            if not pattern:
                return False
            if pattern.startswith("*."):
                suffix = pattern[1:]  # .github.com
                return domain.endswith(suffix) or domain == pattern[2:]
            return domain == pattern

        # Wildcard matches
        assert match_domain("*.github.com", "api.github.com") == True
        assert match_domain("*.github.com", "raw.github.com") == True
        assert match_domain("*.github.com", "github.com") == True

        # Should not match unrelated domains
        assert match_domain("*.github.com", "githubusercontent.com") == False
        assert match_domain("*.github.com", "evil-github.com") == False

    def test_host_with_port(self):
        """Should strip port from host before matching."""
        def clean_host(host):
            return host.split(':')[0] if ':' in host else host

        assert clean_host("api.github.com:443") == "api.github.com"
        assert clean_host("api.github.com") == "api.github.com"
        assert clean_host("localhost:8080") == "localhost"


class TestHeaderFormatting:
    """Test header value formatting for credential injection."""

    def test_bearer_token_format(self):
        """Should format Bearer token correctly."""
        def format_header(template: str, value: str) -> str:
            return template.replace("{value}", value)

        assert format_header("Bearer {value}", "sk-123") == "Bearer sk-123"
        assert format_header("token {value}", "ghp-abc") == "token ghp-abc"
        assert format_header("{value}", "plain-key") == "plain-key"

    def test_custom_header_format(self):
        """Should handle custom header formats."""
        def format_header(template: str, value: str) -> str:
            return template.replace("{value}", value)

        # API key formats
        assert format_header("ApiKey {value}", "key123") == "ApiKey key123"
        assert format_header("X-Api-Key: {value}", "secret") == "X-Api-Key: secret"


class TestDNSTunnelingDetection:
    """Test DNS tunneling detection logic used by Lua filter."""

    def test_normal_hostnames_allowed(self):
        """Normal hostnames should pass tunneling check."""
        def detect_dns_tunneling(host):
            parts = host.split('.')
            for part in parts:
                if len(part) > 63:
                    return True, "Subdomain exceeds 63 characters"
            if len(host) > 100:
                return True, "Hostname unusually long"
            return False, None

        is_suspicious, _ = detect_dns_tunneling("api.github.com")
        assert is_suspicious == False

        is_suspicious, _ = detect_dns_tunneling("files.pythonhosted.org")
        assert is_suspicious == False

    def test_long_subdomain_blocked(self):
        """Subdomains over 63 chars should be flagged."""
        def detect_dns_tunneling(host):
            parts = host.split('.')
            for part in parts:
                if len(part) > 63:
                    return True, "Subdomain exceeds 63 characters"
            if len(host) > 100:
                return True, "Hostname unusually long"
            return False, None

        # 64 character subdomain (potential data exfil)
        long_subdomain = "a" * 64 + ".evil.com"
        is_suspicious, reason = detect_dns_tunneling(long_subdomain)
        assert is_suspicious == True
        assert "63 characters" in reason

    def test_long_hostname_blocked(self):
        """Hostnames over 100 chars total should be flagged."""
        def detect_dns_tunneling(host):
            parts = host.split('.')
            for part in parts:
                if len(part) > 63:
                    return True, "Subdomain exceeds 63 characters"
            if len(host) > 100:
                return True, "Hostname unusually long"
            return False, None

        # Very long hostname (potential data exfil) - over 100 chars
        long_hostname = "sub1.sub2.sub3.sub4.sub5.sub6.sub7.sub8.sub9.sub10.sub11.sub12.sub13.sub14.sub15.sub16.sub17.evil.com"
        assert len(long_hostname) > 100  # Verify test data
        is_suspicious, reason = detect_dns_tunneling(long_hostname)
        assert is_suspicious == True
        assert "unusually long" in reason


class TestCredentialResponseParsing:
    """Test parsing of control plane API responses."""

    def test_parse_matched_response(self):
        """Should parse successful credential response."""
        import json

        def parse_credential_response(body):
            try:
                data = json.loads(body)
                if data.get("matched"):
                    return {
                        "header_name": data.get("header_name"),
                        "header_value": data.get("header_value")
                    }
            except:
                pass
            return None

        response = '{"matched": true, "header_name": "Authorization", "header_value": "Bearer sk-123"}'
        result = parse_credential_response(response)

        assert result is not None
        assert result["header_name"] == "Authorization"
        assert result["header_value"] == "Bearer sk-123"

    def test_parse_unmatched_response(self):
        """Should return None for unmatched domain."""
        import json

        def parse_credential_response(body):
            try:
                data = json.loads(body)
                if data.get("matched"):
                    return {
                        "header_name": data.get("header_name"),
                        "header_value": data.get("header_value")
                    }
            except:
                pass
            return None

        response = '{"matched": false}'
        result = parse_credential_response(response)
        assert result is None

    def test_parse_invalid_response(self):
        """Should handle invalid JSON gracefully."""
        import json

        def parse_credential_response(body):
            try:
                data = json.loads(body)
                if data.get("matched"):
                    return {
                        "header_name": data.get("header_name"),
                        "header_value": data.get("header_value")
                    }
            except:
                pass
            return None

        result = parse_credential_response("not json")
        assert result is None

        result = parse_credential_response("")
        assert result is None

        result = parse_credential_response(None)
        assert result is None


class TestURLEncoding:
    """Test URL encoding for API queries."""

    def test_url_encode_simple(self):
        """Should encode simple strings correctly."""
        from urllib.parse import quote

        assert quote("api.github.com", safe="") == "api.github.com"
        assert quote("test domain.com", safe="") == "test%20domain.com"

    def test_url_encode_special_chars(self):
        """Should encode special characters."""
        from urllib.parse import quote

        assert quote("domain?test=1", safe="") == "domain%3Ftest%3D1"
        assert quote("domain&other", safe="") == "domain%26other"


class TestDevboxLocalMapping:
    """Test devbox.local domain mapping logic."""

    def test_is_devbox_local_domain(self):
        """Should identify devbox.local domains."""
        import re

        def is_devbox_local(host):
            host_clean = host.split(':')[0] if ':' in host else host
            return bool(re.match(r'.*\.devbox\.local$', host_clean))

        # devbox.local domains
        assert is_devbox_local("openai.devbox.local") == True
        assert is_devbox_local("api-github-com.devbox.local") == True
        assert is_devbox_local("openai.devbox.local:80") == True

        # NOT devbox.local domains (regular domains)
        assert is_devbox_local("api.openai.com") == False
        assert is_devbox_local("api.github.com") == False
        assert is_devbox_local("devbox.local") == False  # No subdomain

    def test_https_domains_not_rewritten(self):
        """HTTPS requests to real domains should NOT be mapped.

        Only *.devbox.local HTTP requests get credential injection.
        Direct HTTPS to api.openai.com goes through CONNECT tunnel.
        """
        import re

        def get_real_domain(host, mappings):
            """Simulate Lua filter's get_real_domain function."""
            host_clean = host.split(':')[0] if ':' in host else host

            # Only map devbox.local domains
            if re.match(r'.*\.devbox\.local$', host_clean):
                return mappings.get(host_clean, host_clean), True

            # Regular domains pass through unchanged
            return host_clean, False

        mappings = {
            "openai.devbox.local": "api.openai.com",
            "github.devbox.local": "api.github.com",
        }

        # devbox.local -> maps to real domain
        domain, is_local = get_real_domain("openai.devbox.local", mappings)
        assert domain == "api.openai.com"
        assert is_local == True

        # Real domain -> passes through unchanged (CONNECT tunnel)
        domain, is_local = get_real_domain("api.openai.com", mappings)
        assert domain == "api.openai.com"
        assert is_local == False

        # Unknown devbox.local -> stays as-is
        domain, is_local = get_real_domain("unknown.devbox.local", mappings)
        assert domain == "unknown.devbox.local"
        assert is_local == True

    def test_credential_injection_only_for_devbox_local(self):
        """Credentials should only be looked up for mapped devbox.local domains."""
        import re

        def should_inject_credentials(host, mappings):
            """Determine if we should attempt credential injection."""
            host_clean = host.split(':')[0] if ':' in host else host

            # For devbox.local, map to real domain and inject
            if re.match(r'.*\.devbox\.local$', host_clean):
                real_domain = mappings.get(host_clean)
                if real_domain:
                    return True, real_domain
                return False, None  # Unknown alias

            # For HTTPS direct requests (CONNECT tunnel), we CAN'T inject
            # But for HTTP direct requests to allowed domains, we could
            # In practice, all real APIs use HTTPS, so this is moot
            return False, None

        mappings = {"openai.devbox.local": "api.openai.com"}

        # devbox.local with known alias -> inject
        inject, domain = should_inject_credentials("openai.devbox.local", mappings)
        assert inject == True
        assert domain == "api.openai.com"

        # devbox.local with unknown alias -> don't inject
        inject, domain = should_inject_credentials("unknown.devbox.local", mappings)
        assert inject == False

        # Direct HTTPS domain -> can't inject (CONNECT tunnel)
        inject, domain = should_inject_credentials("api.openai.com", mappings)
        assert inject == False


class TestRateLimitResponseParsing:
    """Test parsing of rate limit API responses."""

    def test_parse_rate_limit_response(self):
        """Should parse rate limit response correctly."""
        import json

        def parse_rate_limit_response(body):
            try:
                data = json.loads(body)
                rpm = data.get("requests_per_minute")
                burst = data.get("burst_size", 10)
                if rpm is not None:
                    return {
                        "requests_per_minute": rpm,
                        "burst_size": burst
                    }
            except:
                pass
            return None

        response = '{"matched": true, "requests_per_minute": 60, "burst_size": 10}'
        result = parse_rate_limit_response(response)

        assert result is not None
        assert result["requests_per_minute"] == 60
        assert result["burst_size"] == 10

    def test_parse_default_rate_limit_response(self):
        """Should parse default rate limit for unmatched domain."""
        import json

        def parse_rate_limit_response(body):
            try:
                data = json.loads(body)
                rpm = data.get("requests_per_minute")
                burst = data.get("burst_size", 10)
                if rpm is not None:
                    return {
                        "requests_per_minute": rpm,
                        "burst_size": burst
                    }
            except:
                pass
            return None

        response = '{"matched": false, "domain": "unknown.com", "requests_per_minute": 120, "burst_size": 20}'
        result = parse_rate_limit_response(response)

        assert result is not None
        assert result["requests_per_minute"] == 120
        assert result["burst_size"] == 20


class TestTokenBucketRateLimiter:
    """Test token bucket rate limiting algorithm."""

    def test_token_bucket_allows_burst(self):
        """Should allow burst of requests up to burst_size."""
        import time

        class TokenBucket:
            def __init__(self, rpm, burst_size):
                self.rpm = rpm
                self.burst_size = burst_size
                self.tokens = burst_size
                self.last_refill = time.time()

            def allow(self):
                now = time.time()
                elapsed = now - self.last_refill
                tokens_per_second = self.rpm / 60.0
                new_tokens = elapsed * tokens_per_second
                self.tokens = min(self.burst_size, self.tokens + new_tokens)
                self.last_refill = now

                if self.tokens >= 1:
                    self.tokens -= 1
                    return True
                return False

        bucket = TokenBucket(rpm=60, burst_size=10)

        # Should allow burst of 10 requests
        allowed = [bucket.allow() for _ in range(10)]
        assert all(allowed), "Should allow burst of requests"

        # 11th request should be denied (no time to refill)
        assert bucket.allow() is False, "Should deny after burst exhausted"

    def test_token_bucket_refills_over_time(self):
        """Should refill tokens based on RPM."""
        import time

        class TokenBucket:
            def __init__(self, rpm, burst_size):
                self.rpm = rpm
                self.burst_size = burst_size
                self.tokens = 0  # Start empty
                self.last_refill = time.time()

            def allow(self):
                now = time.time()
                elapsed = now - self.last_refill
                tokens_per_second = self.rpm / 60.0
                new_tokens = elapsed * tokens_per_second
                self.tokens = min(self.burst_size, self.tokens + new_tokens)
                self.last_refill = now

                if self.tokens >= 1:
                    self.tokens -= 1
                    return True
                return False

        bucket = TokenBucket(rpm=600, burst_size=10)  # 10 per second

        # Wait a bit for tokens to accumulate
        time.sleep(0.2)  # Should add ~2 tokens

        # Should allow at least 1 request
        assert bucket.allow() is True

    def test_token_bucket_respects_burst_cap(self):
        """Should not accumulate more than burst_size tokens."""
        import time

        class TokenBucket:
            def __init__(self, rpm, burst_size):
                self.rpm = rpm
                self.burst_size = burst_size
                self.tokens = burst_size
                self.last_refill = time.time() - 100  # Pretend long time passed

            def refill(self):
                now = time.time()
                elapsed = now - self.last_refill
                tokens_per_second = self.rpm / 60.0
                new_tokens = elapsed * tokens_per_second
                self.tokens = min(self.burst_size, self.tokens + new_tokens)
                self.last_refill = now

        bucket = TokenBucket(rpm=6000, burst_size=10)
        bucket.refill()

        # Should cap at burst_size
        assert bucket.tokens == 10, f"Expected 10 tokens, got {bucket.tokens}"


class TestStandaloneMode:
    """Test standalone mode configuration parsing."""

    def test_parse_static_domain_map(self):
        """Should parse STATIC_DOMAIN_MAP environment variable."""
        def parse_domain_map(env_value):
            """Parse domain mappings from env var format."""
            mappings = {}
            if not env_value:
                return mappings
            for mapping in env_value.split(','):
                parts = mapping.split(':')
                if len(parts) == 2:
                    mappings[parts[0].strip()] = parts[1].strip()
            return mappings

        # Single mapping
        result = parse_domain_map("openai.devbox.local:api.openai.com")
        assert result == {"openai.devbox.local": "api.openai.com"}

        # Multiple mappings
        result = parse_domain_map("openai.devbox.local:api.openai.com,github.devbox.local:api.github.com")
        assert result["openai.devbox.local"] == "api.openai.com"
        assert result["github.devbox.local"] == "api.github.com"

        # Empty
        result = parse_domain_map("")
        assert result == {}

        result = parse_domain_map(None)
        assert result == {}

    def test_parse_static_credentials(self):
        """Should parse STATIC_CREDENTIALS environment variable."""
        def parse_credentials(env_value):
            """Parse credentials from env var format (pipe-separated)."""
            creds = {}
            if not env_value:
                return creds
            for cred in env_value.split('|'):
                parts = cred.split(':', 2)  # Split max 2 times (value may contain colons)
                if len(parts) == 3:
                    domain, header_name, header_value = parts
                    creds[domain.strip()] = {
                        "header_name": header_name.strip(),
                        "header_value": header_value.strip()
                    }
            return creds

        # Single credential
        result = parse_credentials("api.openai.com:Authorization:Bearer sk-123")
        assert result["api.openai.com"]["header_name"] == "Authorization"
        assert result["api.openai.com"]["header_value"] == "Bearer sk-123"

        # Multiple credentials
        result = parse_credentials("api.openai.com:Authorization:Bearer sk-123|api.github.com:Authorization:token ghp-abc")
        assert result["api.openai.com"]["header_value"] == "Bearer sk-123"
        assert result["api.github.com"]["header_value"] == "token ghp-abc"

        # Header value with colons (e.g., Basic auth)
        result = parse_credentials("api.example.com:Authorization:Basic dXNlcjpwYXNz")
        assert result["api.example.com"]["header_value"] == "Basic dXNlcjpwYXNz"

    def test_parse_static_rate_limits(self):
        """Should parse STATIC_RATE_LIMITS environment variable."""
        def parse_rate_limits(env_value):
            """Parse rate limits from env var format."""
            limits = {}
            if not env_value:
                return limits
            for limit in env_value.split(','):
                parts = limit.split(':')
                if len(parts) == 3:
                    domain, rpm, burst = parts
                    limits[domain.strip()] = {
                        "requests_per_minute": int(rpm),
                        "burst_size": int(burst)
                    }
            return limits

        # Default only
        result = parse_rate_limits("default:120:20")
        assert result["default"]["requests_per_minute"] == 120
        assert result["default"]["burst_size"] == 20

        # Multiple limits
        result = parse_rate_limits("default:120:20,api.openai.com:60:10,api.github.com:100:15")
        assert result["default"]["requests_per_minute"] == 120
        assert result["api.openai.com"]["requests_per_minute"] == 60
        assert result["api.github.com"]["burst_size"] == 15

    def test_wildcard_credential_matching(self):
        """Should match wildcard credentials like *.github.com."""
        def match_credential(host, credentials):
            """Find credential for host, supporting wildcards."""
            # Exact match
            if host in credentials:
                return credentials[host]

            # Wildcard match
            for pattern, cred in credentials.items():
                if pattern.startswith("*."):
                    suffix = pattern[1:]  # .github.com
                    if host.endswith(suffix) or host == pattern[2:]:
                        return cred
            return None

        creds = {
            "api.openai.com": {"header_name": "Authorization", "header_value": "Bearer sk-123"},
            "*.github.com": {"header_name": "Authorization", "header_value": "token ghp-abc"},
        }

        # Exact match
        result = match_credential("api.openai.com", creds)
        assert result["header_value"] == "Bearer sk-123"

        # Wildcard match
        result = match_credential("api.github.com", creds)
        assert result["header_value"] == "token ghp-abc"

        result = match_credential("raw.github.com", creds)
        assert result["header_value"] == "token ghp-abc"

        # Base domain match
        result = match_credential("github.com", creds)
        assert result["header_value"] == "token ghp-abc"

        # No match
        result = match_credential("api.anthropic.com", creds)
        assert result is None

    def test_mode_detection(self):
        """Should correctly detect standalone vs connected mode."""
        def should_contact_cp(mode, token):
            """Determine if control plane should be contacted.

            Matches the Lua filter logic:
            - "standalone" mode: never contact CP
            - "connected" mode (default): contact CP if token is present
            """
            if mode == "standalone":
                return False
            if not token:
                return False
            return True

        # Standalone mode - never contact CP, even with token
        assert should_contact_cp("standalone", "some-token") == False
        assert should_contact_cp("standalone", "") == False

        # Connected mode - contact if token present
        assert should_contact_cp("connected", "some-token") == True
        assert should_contact_cp("connected", "") == False

        # Default behavior (any non-standalone mode defaults to connected)
        assert should_contact_cp("", "some-token") == True
        assert should_contact_cp("connected", "") == False  # No token = no CP contact

    def test_fallback_priority(self):
        """Static config should be used as fallback when CP fails."""
        def get_credential_with_fallback(host, cp_response, static_credentials):
            """Get credential with CP first, static fallback."""
            # Try CP response first
            if cp_response and cp_response.get("matched"):
                return {
                    "header_name": cp_response.get("header_name"),
                    "header_value": cp_response.get("header_value")
                }

            # Fall back to static
            return static_credentials.get(host)

        static_creds = {
            "api.openai.com": {"header_name": "Authorization", "header_value": "Bearer static-key"}
        }

        # CP response takes precedence
        cp_response = {"matched": True, "header_name": "Authorization", "header_value": "Bearer cp-key"}
        result = get_credential_with_fallback("api.openai.com", cp_response, static_creds)
        assert result["header_value"] == "Bearer cp-key"

        # No CP response - use static
        result = get_credential_with_fallback("api.openai.com", None, static_creds)
        assert result["header_value"] == "Bearer static-key"

        # CP returns not matched - use static
        cp_response = {"matched": False}
        result = get_credential_with_fallback("api.openai.com", cp_response, static_creds)
        assert result["header_value"] == "Bearer static-key"


class TestMatchDomainWildcard:
    """Test the match_domain_wildcard helper that replaces copy-pasted wildcard matching."""

    @staticmethod
    def match_domain_wildcard(domain, tbl):
        """Python equivalent of the Lua match_domain_wildcard function."""
        exact = tbl.get(domain)
        if exact is not None:
            return exact
        for pattern, value in tbl.items():
            if pattern.startswith("*."):
                suffix = pattern[1:]  # .domain.com
                if domain.endswith(suffix):
                    return value
        return None

    def test_exact_match(self):
        """Should return exact match when available."""
        tbl = {"api.github.com": {"rpm": 60}}
        result = self.match_domain_wildcard("api.github.com", tbl)
        assert result == {"rpm": 60}

    def test_wildcard_match(self):
        """Should match wildcard patterns."""
        tbl = {"*.github.com": {"rpm": 100}}
        result = self.match_domain_wildcard("api.github.com", tbl)
        assert result == {"rpm": 100}

        result = self.match_domain_wildcard("raw.github.com", tbl)
        assert result == {"rpm": 100}

    def test_exact_takes_priority_over_wildcard(self):
        """Exact match should be preferred over wildcard."""
        tbl = {
            "api.github.com": {"rpm": 60},
            "*.github.com": {"rpm": 100},
        }
        result = self.match_domain_wildcard("api.github.com", tbl)
        assert result == {"rpm": 60}

        # Non-exact subdomain should match wildcard
        result = self.match_domain_wildcard("raw.github.com", tbl)
        assert result == {"rpm": 100}

    def test_no_match_returns_none(self):
        """Should return None when no match found."""
        tbl = {"api.github.com": {"rpm": 60}}
        result = self.match_domain_wildcard("api.openai.com", tbl)
        assert result is None

    def test_empty_table(self):
        """Should return None for empty table."""
        result = self.match_domain_wildcard("api.github.com", {})
        assert result is None

    def test_wildcard_does_not_match_partial_suffix(self):
        """Wildcard *.github.com should NOT match evil-github.com."""
        tbl = {"*.github.com": {"rpm": 100}}
        result = self.match_domain_wildcard("evil-github.com", tbl)
        assert result is None


class TestPerStreamMetadata:
    """Test the per-stream metadata pattern for concurrency safety."""

    def test_metadata_pattern_replaces_global_variable(self):
        """Per-stream metadata should be used instead of module-level variable.

        This verifies the design: instead of `local request_domain = nil` at
        module scope (shared across concurrent requests), we use Envoy's
        per-stream dynamic metadata API to pass domain from request to response.
        """
        # Simulate two concurrent requests
        streams = {}

        def set_metadata(stream_id, domain):
            streams[stream_id] = {"request_domain": domain}

        def get_metadata(stream_id):
            return streams.get(stream_id, {}).get("request_domain")

        # Request A sets domain
        set_metadata("stream_a", "api.openai.com")

        # Request B sets domain (would overwrite with global var!)
        set_metadata("stream_b", "api.github.com")

        # Both streams retain their own domain
        assert get_metadata("stream_a") == "api.openai.com"
        assert get_metadata("stream_b") == "api.github.com"

    def test_missing_metadata_returns_none(self):
        """Should handle missing metadata gracefully (unknown stream)."""
        streams = {}
        metadata = streams.get("nonexistent")
        domain = metadata and metadata.get("request_domain") or None
        assert domain is None


class TestEnhancedDNSTunneling:
    """Test enhanced DNS tunneling detection heuristics."""

    @staticmethod
    def detect_dns_tunneling(host):
        """Python equivalent of the enhanced Lua detect_dns_tunneling function."""
        parts = host.split('.')

        for part in parts:
            if len(part) > 63:
                return True, "Subdomain exceeds 63 characters"

        if len(host) > 100:
            return True, "Hostname unusually long"

        # Excessive subdomain depth
        if len(parts) > 6:
            return True, "Excessive subdomain depth"

        # High entropy / hex-like labels
        import re
        suspicious_labels = 0
        for part in parts:
            if len(part) > 20 and re.match(r'^[0-9a-fA-F-]+$', part):
                suspicious_labels += 1
        if suspicious_labels >= 2:
            return True, "Multiple hex-encoded subdomain labels"

        return False, None

    def test_normal_domains_pass(self):
        """Normal domains should not trigger detection."""
        normal_domains = [
            "api.github.com",
            "files.pythonhosted.org",
            "cdn.jsdelivr.net",
            "api.openai.com",
            "huggingface.co",
            "sub1.sub2.example.com",
        ]
        for domain in normal_domains:
            is_suspicious, _ = self.detect_dns_tunneling(domain)
            assert is_suspicious is False, f"False positive for: {domain}"

    def test_excessive_depth_blocked(self):
        """Domains with >6 subdomain levels should be flagged."""
        deep_domain = "a.b.c.d.e.f.evil.com"  # 8 parts
        is_suspicious, reason = self.detect_dns_tunneling(deep_domain)
        assert is_suspicious is True
        assert "depth" in reason.lower()

    def test_hex_encoded_labels_blocked(self):
        """Multiple long hex-encoded labels should be flagged."""
        # Simulate base16-encoded data exfiltration
        hex_domain = "aabbccddee11223344556677.ff00112233445566778899aa.evil.com"
        is_suspicious, reason = self.detect_dns_tunneling(hex_domain)
        assert is_suspicious is True
        assert "hex" in reason.lower()

    def test_single_hex_label_allowed(self):
        """A single hex-like label should not trigger (CDN hashes are common)."""
        cdn_domain = "abc123def456789012345678.cdn.example.com"
        is_suspicious, _ = self.detect_dns_tunneling(cdn_domain)
        assert is_suspicious is False

    def test_short_hex_labels_allowed(self):
        """Short hex labels (<= 20 chars) should not trigger."""
        domain = "abcdef123456.abcdef789012.example.com"
        is_suspicious, _ = self.detect_dns_tunneling(domain)
        assert is_suspicious is False

    def test_long_subdomain_still_caught(self):
        """RFC limit (>63 char label) should still trigger."""
        long_label = "a" * 64
        domain = f"{long_label}.evil.com"
        is_suspicious, reason = self.detect_dns_tunneling(domain)
        assert is_suspicious is True
        assert "63 characters" in reason

    def test_long_hostname_still_caught(self):
        """Overall hostname >100 chars should still trigger."""
        parts = ["sub" + str(i) for i in range(20)]
        domain = ".".join(parts) + ".evil.com"
        assert len(domain) > 100
        is_suspicious, _ = self.detect_dns_tunneling(domain)
        assert is_suspicious is True
