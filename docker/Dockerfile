FROM rust:bookworm AS builder

# The operator image runs native ETH API, indexer and challenge services.
# The browser SDK and host application build separately.
WORKDIR /app

# Unset (the default): the daemons accept only the pinned ceremony keys
# (mpc-1). 1: a single-party build for a vault deployed with Deploy.s.sol's
# ALLOW_DEV_SETUP=1, whose setup's generator can forge every proof: the
# daemons get zkapi-proof's dev-setup feature and the image installs the
# development setup instead of the ceremony's.
ARG ALLOW_DEV_SETUP=

COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY protocol ./protocol

RUN case "$ALLOW_DEV_SETUP" in \
        '' | 1) ;; \
        *) echo "ALLOW_DEV_SETUP must be 1 or unset" >&2; exit 1 ;; \
    esac \
    && cargo build --locked --release ${ALLOW_DEV_SETUP:+--features=zkapi-proof/dev-setup} \
        -p zkapi-cli -p zkapi-indexerd -p zkapi-serverd --bins

FROM debian:bookworm-slim

ARG ALLOW_DEV_SETUP=

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 zkapi

WORKDIR /srv/zkapi

COPY --from=builder /app/target/release/zkapi /usr/local/bin/zkapi
COPY --from=builder /app/target/release/zkapi-indexerd /usr/local/bin/zkapi-indexerd
COPY --from=builder /app/target/release/zkapi-challenged /usr/local/bin/zkapi-challenged
# The setup of circuit zkapi-v2-concession-v1 the daemons load. By default the
# ceremony setup: a release build loads only its pinned mpc-1 keys, which
# G-SETUP commits, and until then the daemons refuse to start. With
# ALLOW_DEV_SETUP=1, the single-party development setup.
COPY --from=builder /app/protocol/setup/v2-concession${ALLOW_DEV_SETUP:+-dev} /srv/zkapi/protocol/setup/v2-concession${ALLOW_DEV_SETUP:+-dev}
ENV ZKAPI_PROOF_SETUP_DIR=/srv/zkapi/protocol/setup/v2-concession${ALLOW_DEV_SETUP:+-dev}

COPY --chmod=755 docker/aws/run-daemon.sh /usr/local/bin/zkapi-run

USER zkapi

ENV RUST_LOG=info
VOLUME ["/data"]

ENTRYPOINT ["zkapi-run"]
CMD ["server"]
