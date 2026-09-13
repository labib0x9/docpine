FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    llvm \
    libelf-dev \
    linux-headers-generic \
    bpftool \
    pkg-config \
    git \
    curl \
    wget \
    ca-certificates \
    iproute2 \
    iptables \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Install Go 1.22+
ENV GO_VERSION=1.22.6
RUN curl -fsSL https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz | tar -C /usr/local -xz
ENV PATH=$PATH:/usr/local/go/bin

WORKDIR /workspace
CMD ["/bin/bash"]
