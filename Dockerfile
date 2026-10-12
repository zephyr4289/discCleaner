# diskCleaner OCI image (v0.9.0, Phase 3 — Enterprise Distribution)
#
# A minimal, container-native sanitization agent for fleet and DaemonSet
# deployments. `dc` needs direct block-device access: run privileged with
# host devices mounted, e.g.
#
#   docker run --rm --privileged -v /dev:/dev \
#     -v $PWD/certs:/certs ghcr.io/zephyr4289/discleaner:latest \
#     dc list --json
#
# The image is distroless-class (debian:bookworm-slim runtime): no shell,
# no package manager, no init — the attack surface is the dc binary itself.
# Static musl builds are shipped separately for bare-metal/ISO appliance
# use cases (see scripts/build-appliance.sh).

FROM rust:1-bookworm AS builder

WORKDIR /build

# Dependency layer (cached across source edits).
COPY Cargo.toml Cargo.lock ./
COPY crates/ crates/
COPY docs/ docs/

# Release build of the CLI binaries.
RUN cargo build --release -p dc-cli

# --- runtime ----------------------------------------------------------------
FROM debian:bookworm-slim

LABEL org.opencontainers.image.title="diskCleaner"
LABEL org.opencontainers.image.description="Forensic-grade storage sanitization: NIST SP 800-88 / IEEE 2883 with TPM-attested evidence"
LABEL org.opencontainers.image.source="https://github.com/zephyr4289/discCleaner"
LABEL org.opencontainers.image.licenses="MIT OR Apache-2.0"

COPY --from=builder /build/target/release/dc /usr/local/bin/dc
COPY --from=builder /build/target/release/diskcleaner /usr/local/bin/diskcleaner

# Non-root by default; block-device operations require the operator to
# elevate intentionally (docker run --privileged / k8s privileged DaemonSet).
RUN useradd --system --no-create-home --shell /usr/sbin/nologin dcuser
USER dcuser

# Machine-parsable fleet contract is the default container contract.
ENTRYPOINT ["dc"]
CMD ["--version"]
