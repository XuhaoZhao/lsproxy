FROM rust:1.81.0-slim-bookworm

# Set the working directory in the container
WORKDIR /usr/src/app

# Install runtime and development dependencies, Python, Node.js, and npm
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    libssl3 \
    ca-certificates \
    git \
    python3 \
    python3-pip \
    python3-venv \
    curl \
    clangd \
    build-essential \
    gcc \
    g++ \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y nodejs \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Java
RUN apt-get update && \
    apt-get install -y openjdk-17-jdk \
    gradle \
    maven \
    && \
    curl -L -o /tmp/jdt-language-server.tar.gz https://www.eclipse.org/downloads/download.php?file=/jdtls/snapshots/jdt-language-server-latest.tar.gz && \
    mkdir -p /opt/jdtls && \
    tar -xzf /tmp/jdt-language-server.tar.gz -C /opt/jdtls && \
    rm /tmp/jdt-language-server.tar.gz

# Add jdtls to PATH
ENV PATH="/opt/jdtls/bin:${PATH}"

# Install rust-analyzer and rustfmt
RUN rustup component add rust-analyzer
RUN rustup component add rustfmt

# Create a virtual environment
RUN python3 -m venv /app/venv
ENV PATH="/app/venv/bin:$PATH"

# Install jedi python language server, ast grep for tree sitter
RUN pip install jedi-language-server ast-grep-cli

# Install global npm packages
RUN npm install -g typescript-language-server typescript

# Install coverage tools
RUN cargo install cargo-llvm-cov
RUN rustup component add llvm-tools-preview

COPY Cargo.toml .

RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN touch src/lib.rs
RUN cargo build --release

RUN cargo install ast-grep --locked
COPY ./src/ast_grep /usr/src/ast_grep

# Document that the container listens on port 4444
EXPOSE 4444

# Set environment variables for logging and backtrace
ENV RUST_LOG=debug,glob=info,ignore=info
ENV RUST_BACKTRACE=1
ENV RA_LOG="/tmp/rust-analyzer.log"

CMD /bin/bash -c "touch Cargo.toml && cargo build --release"
