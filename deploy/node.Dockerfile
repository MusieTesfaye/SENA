# The SENA node, with the Aptos CLI the relayer and watcher sign through.
# Builds natively on the host's architecture (arm64 on an Oracle Ampere VM).
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p sena-node

FROM debian:bookworm-slim
ARG APTOS_CLI_VERSION=7.9.0
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl unzip git python3 libssl3 \
 && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    case "$(uname -m)" in x86_64) a=x86_64 ;; aarch64) a=aarch64 ;; *) echo "unsupported $(uname -m)"; exit 1 ;; esac; \
    curl -fsSL -o /tmp/aptos.zip "https://github.com/aptos-labs/aptos-core/releases/download/aptos-cli-v${APTOS_CLI_VERSION}/aptos-cli-${APTOS_CLI_VERSION}-Linux-${a}.zip"; \
    unzip -o /tmp/aptos.zip -d /usr/local/bin; rm /tmp/aptos.zip; aptos --version
COPY --from=build /src/target/release/sena-node /usr/local/bin/sena-node
COPY move /opt/sena/move
COPY deploy /opt/sena/deploy
WORKDIR /data
