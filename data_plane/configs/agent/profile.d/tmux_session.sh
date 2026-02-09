#!/bin/bash
# =============================================================================
# Auto-attach to tmux session on SSH login
# Provides persistent sessions that survive disconnects
#
# Environment variables:
#   TMUX_AUTO_ATTACH=0    Disable auto-attach (manual tmux management)
#   TMUX_SESSION=name     Custom session name (default: main)
# =============================================================================

# Skip if auto-attach is disabled
if [[ "${TMUX_AUTO_ATTACH:-1}" == "0" ]]; then
    return 0
fi

# Only run in interactive shells and SSH sessions
if [[ -z "$TMUX" && -n "$SSH_CONNECTION" && $- == *i* ]]; then

    # Session name (default: main, can be overridden)
    SESSION_NAME="${TMUX_SESSION:-main}"

    # Ensure tmux socket directory exists
    TMUX_SOCKET_DIR="/workspace/.tmux"
    mkdir -p "$TMUX_SOCKET_DIR"
    export TMUX_TMPDIR="$TMUX_SOCKET_DIR"

    # Check if session exists
    if tmux has-session -t "$SESSION_NAME" 2>/dev/null; then
        echo "Attaching to existing tmux session: $SESSION_NAME"
        echo "(Detach: Ctrl-a d | New window: Ctrl-a c | Help: session --help)"
        echo ""
        exec tmux attach-session -t "$SESSION_NAME"
    else
        echo "Creating new tmux session: $SESSION_NAME"
        echo "(Detach: Ctrl-a d | New window: Ctrl-a c | Help: session --help)"
        echo ""
        exec tmux new-session -s "$SESSION_NAME"
    fi
fi
