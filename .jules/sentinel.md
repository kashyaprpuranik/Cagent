## 2024-05-22 - Unrestricted Container Log Access
**Vulnerability:** IDOR in log endpoints allowing access to any container on the host.
**Learning:** `docker_client.containers.get(name)` accepts any container name/ID, not just those managed by the application.
**Prevention:** Always validate user-supplied resource identifiers against a whitelist of allowed resources before accessing them.
