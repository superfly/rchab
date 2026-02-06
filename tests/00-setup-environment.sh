#!/bin/bash
set -euo pipefail

echo "=== Setting up Docker for testing ==="

# Install Docker if not present
if ! command -v docker &> /dev/null; then
    echo "Installing Docker..."
    sudo apt-get update
    sudo apt-get install -y \
        ca-certificates \
        curl \
        gnupg \
        lsb-release

    # Add Docker's official GPG key
    sudo install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | \
        sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    sudo chmod a+r /etc/apt/keyrings/docker.gpg

    # Set up repository (use jammy for compatibility)
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      jammy stable" | \
      sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

    # Install Docker Engine
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin

    # Add sprite user to docker group
    sudo usermod -aG docker sprite

    # Start Docker service
    sudo systemctl start docker
    sudo systemctl enable docker

    echo "✓ Docker installed successfully"
else
    echo "✓ Docker already installed"
fi

# Verify Docker installation
echo ""
echo "=== Docker Version Check ==="
docker --version
docker compose version || true
docker buildx version

# Verify we can run containers
echo ""
echo "=== Testing Docker Functionality ==="
docker run --rm hello-world

echo ""
echo "✓ Environment setup complete!"
