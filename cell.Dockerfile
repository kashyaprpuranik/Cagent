# =============================================================================
# AI Cell Development Environment
# =============================================================================
#
# Build variants (use --build-arg VARIANT=<name>):
#   lean - Essentials only (~1.5GB)
#   dev  - Essentials + Go + Rust + Cloud CLIs (~3GB)
#   ml   - Dev + PyTorch + ML libs (~6GB)
#
# Usage:
#   docker build -f cell.Dockerfile --build-arg VARIANT=lean -t cell:lean .
#   docker build -f cell.Dockerfile --build-arg VARIANT=dev -t cell:dev .
#   docker build -f cell.Dockerfile --build-arg VARIANT=ml -t cell:ml .
#
# =============================================================================

FROM ubuntu:22.04

ARG VARIANT=lean
ARG DEBIAN_FRONTEND=noninteractive

# Labels
LABEL maintainer="AI Devbox"
LABEL variant="${VARIANT}"

# =============================================================================
# Base: Core utilities (all variants)
# =============================================================================
RUN apt-get update && apt-get install -y --no-install-recommends \
    # SSH Server
    openssh-server \
    # Core utilities
    curl \
    wget \
    git \
    vim \
    nano \
    htop \
    jq \
    tree \
    unzip \
    zip \
    tmux \
    less \
    file \
    ca-certificates \
    gnupg \
    lsb-release \
    sudo \
    locales \
    # Build essentials
    build-essential \
    cmake \
    make \
    pkg-config \
    # Python
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    # Network tools
    netcat-openbsd \
    dnsutils \
    iputils-ping \
    net-tools \
    # DB clients
    postgresql-client \
    redis-tools \
    # Misc
    software-properties-common \
    && rm -rf /var/lib/apt/lists/*

# Set locale
RUN locale-gen en_US.UTF-8
ENV LANG=en_US.UTF-8
ENV LC_ALL=en_US.UTF-8

# =============================================================================
# Node.js (all variants)
# =============================================================================
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && npm install -g yarn \
    && rm -rf /var/lib/apt/lists/*

# =============================================================================
# Python packages (all variants)
# =============================================================================
RUN pip3 install --no-cache-dir \
    requests \
    httpx \
    pyyaml \
    python-dotenv \
    rich \
    click \
    typer

# =============================================================================
# Dev variant: Go, Rust, Cloud CLIs
# =============================================================================
RUN if [ "$VARIANT" = "dev" ] || [ "$VARIANT" = "ml" ]; then \
    # Go
    curl -fsSL https://go.dev/dl/go1.22.0.linux-amd64.tar.gz | tar -C /usr/local -xzf - \
    && echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile.d/go.sh \
    # Rust
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y \
    && echo 'source $HOME/.cargo/env' >> /etc/profile.d/rust.sh \
    # AWS CLI
    && curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "/tmp/awscliv2.zip" \
    && unzip -q /tmp/awscliv2.zip -d /tmp \
    && /tmp/aws/install \
    && rm -rf /tmp/aws /tmp/awscliv2.zip \
    # Docker CLI (for container management)
    && curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo "deb [arch=amd64 signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" > /etc/apt/sources.list.d/docker.list \
    && apt-get update && apt-get install -y docker-ce-cli \
    && rm -rf /var/lib/apt/lists/* \
    ; fi

# =============================================================================
# ML variant: PyTorch, numpy, pandas, scikit-learn
# =============================================================================
RUN if [ "$VARIANT" = "ml" ]; then \
    pip3 install --no-cache-dir \
        torch --index-url https://download.pytorch.org/whl/cpu \
    && pip3 install --no-cache-dir \
        numpy \
        pandas \
        scipy \
        scikit-learn \
        matplotlib \
        seaborn \
        jupyter \
        ipython \
        transformers \
        datasets \
        accelerate \
    ; fi

# =============================================================================
# SSH Configuration
# =============================================================================
RUN mkdir -p /var/run/sshd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config \
    && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config \
    && sed -i 's/#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config

# =============================================================================
# Create non-root user
# =============================================================================
ARG USER_NAME=cell
ARG USER_UID=1000
ARG USER_GID=1000

RUN groupadd --gid $USER_GID $USER_NAME \
    && useradd --uid $USER_UID --gid $USER_GID -m -s /bin/bash $USER_NAME \
    && echo "$USER_NAME ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers.d/$USER_NAME \
    && chmod 0440 /etc/sudoers.d/$USER_NAME

# SSH directory for user
RUN mkdir -p /home/$USER_NAME/.ssh \
    && chmod 700 /home/$USER_NAME/.ssh \
    && chown -R $USER_NAME:$USER_NAME /home/$USER_NAME/.ssh

# =============================================================================
# Workspace
# =============================================================================
RUN mkdir -p /workspace && chown $USER_NAME:$USER_NAME /workspace
WORKDIR /workspace

# =============================================================================
# Persistent Sessions (tmux)
# =============================================================================
# Tmux configuration
COPY configs/cell/tmux.conf /etc/tmux.conf

# Auto-attach to tmux on SSH login
COPY configs/cell/profile.d/tmux_session.sh /etc/profile.d/99-tmux-session.sh
RUN chmod +x /etc/profile.d/99-tmux-session.sh

# Session management helper
COPY configs/cell/bin/session /usr/local/bin/session
RUN chmod +x /usr/local/bin/session

# =============================================================================
# Seed traffic script (for dev_up.sh log seeding)
# =============================================================================
COPY scripts/seed_traffic.py /seed_traffic.py

# =============================================================================
# Entrypoint
# =============================================================================
COPY cell_entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 22

# Start SSH and keep container running
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
