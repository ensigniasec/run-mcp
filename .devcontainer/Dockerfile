# syntax=docker/dockerfile:1

# Use the official Dev Containers Go image (includes non-root user `vscode`)
ARG VARIANT=1-bookworm
FROM mcr.microsoft.com/devcontainers/go:${VARIANT}

ENV DEBIAN_FRONTEND=noninteractive \
    GOTOOLCHAIN=go1.25.0 \
    GOFLAGS=-buildvcs=false \
    GOPROXY=https://proxy.golang.org,direct \
    GOSUMDB=sum.golang.org

# Install system deps and `entr`
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    entr \
    && rm -rf /var/lib/apt/lists/*

# Install Task (https://taskfile.dev)
RUN curl -sSfL https://taskfile.dev/install.sh | sh -s -- -b /usr/local/bin

# Pre-create common directories to speed up initial `go mod download`
RUN mkdir -p /go/pkg/mod /go/pkg/mod/cache /workspaces/run-mcp && \
    chown -R vscode:vscode /go && \
    chown -R vscode:vscode /workspaces/run-mcp

# Set default workdir; VS Code Dev Containers will mount the repo here
WORKDIR /workspaces/run-mcp

# Keep default user as created by base image
USER vscode
