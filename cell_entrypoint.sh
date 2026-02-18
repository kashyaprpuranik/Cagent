#!/bin/bash
set -e

# =============================================================================
# Cell Container Entrypoint
# Starts SSH server with persistent tmux sessions
# =============================================================================

USER_NAME="${USER_NAME:-cell}"
USER_HOME="/home/$USER_NAME"
WORKSPACE="/workspace"

# Setup SSH authorized keys from environment or mounted file
setup_ssh_keys() {
    local auth_keys_file="$USER_HOME/.ssh/authorized_keys"

    # From environment variable
    if [ -n "$SSH_AUTHORIZED_KEYS" ]; then
        echo "Setting up SSH keys from environment..."
        echo "$SSH_AUTHORIZED_KEYS" > "$auth_keys_file"
    fi

    # From mounted file (appends if env keys exist)
    if [ -f "/ssh-keys/authorized_keys" ]; then
        echo "Appending SSH keys from mounted file..."
        cat /ssh-keys/authorized_keys >> "$auth_keys_file"
    fi

    # Set permissions
    if [ -f "$auth_keys_file" ]; then
        chmod 600 "$auth_keys_file"
        chown "$USER_NAME:$USER_NAME" "$auth_keys_file"
        echo "SSH keys configured for user $USER_NAME"
    else
        echo "WARNING: No SSH keys configured. SSH login will fail."
        echo "Set SSH_AUTHORIZED_KEYS env var or mount keys to /ssh-keys/authorized_keys"
    fi
}

# Generate host keys if missing
setup_host_keys() {
    if [ ! -f /etc/ssh/ssh_host_rsa_key ]; then
        echo "Generating SSH host keys..."
        ssh-keygen -A
    fi
}

# Setup persistent tmux sessions
setup_tmux() {
    local tmux_dir="$WORKSPACE/.tmux"
    local tmux_conf="$USER_HOME/.tmux.conf"

    # Create tmux socket directory on persistent volume
    mkdir -p "$tmux_dir"
    chown "$USER_NAME:$USER_NAME" "$tmux_dir"
    chmod 700 "$tmux_dir"

    # Copy tmux config if not customized by user
    if [ -f "/etc/tmux.conf" ] && [ ! -f "$tmux_conf" ]; then
        cp /etc/tmux.conf "$tmux_conf"
        chown "$USER_NAME:$USER_NAME" "$tmux_conf"
    fi

    # Set tmux socket directory environment
    echo "export TMUX_TMPDIR=$tmux_dir" >> /etc/profile.d/tmux-env.sh

    echo "Tmux configured with persistent sessions at $tmux_dir"
}

# Recover existing tmux sessions after container restart
recover_tmux_sessions() {
    local tmux_dir="$WORKSPACE/.tmux"

    # Check if there are existing tmux sockets
    if [ -d "$tmux_dir" ]; then
        local socket_count=$(find "$tmux_dir" -name "default" -type s 2>/dev/null | wc -l)
        if [ "$socket_count" -gt 0 ]; then
            echo "Found existing tmux sessions (will be available on SSH login)"
        fi
    fi
}

# Main
echo "=== AI Cell Container Starting ==="
echo "Variant: ${VARIANT:-lean}"
echo "User: $USER_NAME"

setup_host_keys
setup_ssh_keys
setup_tmux
recover_tmux_sessions

# Start SSH daemon
echo "Starting SSH server..."
/usr/sbin/sshd

# Keep container running
echo ""
echo "Cell ready!"
echo "  - SSH: port 22"
echo "  - Sessions: auto-attach to tmux on login"
echo "  - Workspace: $WORKSPACE (persistent)"
echo ""
exec tail -f /dev/null
