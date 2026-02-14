# Container Hardening Plan

## Status: Planned (not yet implemented)

## Overview

Add container-level hardening controls to security profiles, beyond the existing seccomp syscall filtering. These controls restrict filesystem access, privilege escalation, and available tooling inside agent containers.

## Design: Hardening Tier with Individual Overrides (Hybrid)

A `hardening_tier` field acts as a **preset** that pre-fills individual fields. Users can override any field, switching the tier to `custom`.

### Tier Definitions

| Tier | Seccomp | Sudo | Root FS | tmpfs | Image |
|------|---------|------|---------|-------|-------|
| `permissive` | permissive | allowed | read-write | exec | full |
| `standard` | standard | allowed | read-write | exec | full |
| `hardened` | hardened | disabled | read-only | noexec | full |
| `locked` | hardened | disabled | read-only | noexec | minimal |
| `custom` | (any) | (any) | (any) | (any) | (any) |

### New SecurityProfile Fields

```
hardening_tier:   permissive | standard | hardened | locked | custom
seccomp_profile:  standard | hardened | permissive           (existing)
disable_sudo:     bool                                       (new)
read_only_rootfs: bool                                       (new)
noexec_tmpfs:     bool                                       (new)
image_tier:       full | standard | minimal | locked         (new)
```

### UI Behavior

- Profile creation/edit modal: tier dropdown at the top
- Selecting a tier pre-fills all individual fields
- Expandable "Advanced" section shows individual fields
- Changing any individual field switches dropdown to "Custom"
- Existing profiles get `hardening_tier = custom` (migration-safe)

## Individual Controls

### disable_sudo (bool)

Prevents privilege escalation inside the container.

- When `true`: removes sudoers entry or mounts `/etc/sudoers.d` as empty read-only
- Prevents `sudo apt install`, `sudo iptables`, etc.

### read_only_rootfs (bool)

Makes the container's root filesystem read-only via Docker's `ReadonlyRootfs` flag.

- Prevents modification of system binaries, configs, cron dirs
- Writable paths: `/workspace` (Docker volume), `/tmp` and `/var/tmp` (tmpfs)
- **Requires container restart** (not hot-updatable like CPU/memory)

### noexec_tmpfs (bool)

Mounts `/tmp` and `/var/tmp` with `noexec` flag.

```python
"Tmpfs": {
    "/tmp": "rw,noexec,nosuid,size=500m",
    "/var/tmp": "rw,noexec,nosuid,size=100m",
}
```

- Prevents execution of downloaded binaries in temp directories
- Agent can still write files, just not execute them
- Bypass: interpreted scripts (`python3 script.py`) still work — this is defense-in-depth

### image_tier (enum)

Controls which tools are available in the agent container image.

| Tier | Included | Excluded |
|------|----------|----------|
| `full` | Everything (current default) | Nothing |
| `standard` | python, node, git, vim | curl, wget, nc, build-essential, sudo |
| `minimal` | python, node | git, vim, curl, wget, nc, sudo, build-essential, go, rust |
| `locked` | python only | Everything else |

- Requires building multiple image variants (can share base layers)
- Agent manager selects image based on this field
- **Requires container recreation** (not hot-updatable)

## Implementation Notes

### Backend Changes

- `models.py`: Add new columns to `SecurityProfile` (with defaults for migration)
- `schemas.py`: Add `HardeningTier`, `ImageTier` enums, update profile schemas
- `routes/security_profiles.py`: Handle tier preset logic
- `routes/agents.py`: Include new fields in heartbeat response

### Agent Manager Changes

- `main.py`: Apply `disable_sudo`, `read_only_rootfs`, `noexec_tmpfs` during container recreation
- Container recreation already exists for seccomp changes — extend it
- `image_tier` requires selecting the right Docker image tag

### Frontend Changes

- Profile modal: Add tier dropdown + advanced section
- Profile table: Show hardening tier column

### Image Build Changes

- `agent.Dockerfile`: Add build stages/targets for each image tier
- CI: Build and tag all tier variants

## Enforcement Layers (Defense in Depth)

1. **Kernel** — Seccomp syscall filtering (existing)
2. **Container** — Read-only rootfs, noexec tmpfs, no sudo (new)
3. **Image** — Reduced toolset (new)
4. **Network** — DNS + HTTP proxy filtering (existing)
5. **gVisor** — User-space syscall interception (existing, optional)

## Other Policy Categories Considered (Future)

- **Filesystem policies**: Disk quotas, writable path allowlists, file type restrictions
- **Time/session policies**: Max session duration, idle timeout, scheduled windows
- **DLP (Data Loss Prevention)**: Regex scanning of outbound request bodies
- **Cost/budget policies**: LLM API token tracking, budget ceilings
- **Command execution policies**: AppArmor profiles, restricted shell
- **Outbound connection policies**: Protocol allowlists, connection limits
- **Package/dependency policies**: Package name allowlists, vulnerability gates
- **Secrets access policies**: Per-agent secret visibility, usage logging
- **Git/VCS policies**: Repo allowlists, branch restrictions
- **Inter-agent policies**: Agent-to-agent communication rules
