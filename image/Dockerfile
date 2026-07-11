# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# Both build and runtime roots are immutable linux/amd64 manifests. The runtime
# root supplies Chromium and its complete OS dependency set, so this build never
# invokes an OS package manager or a browser dependency installer.
ARG RUST_VERSION=1.96.0

FROM rust:1.96.0-bookworm@sha256:c993d32d95cc146bd12c84d66f0b924a6a96f3988325f39c144f2f9893dea120 AS build

ARG RUST_VERSION
ARG SOURCE_DATE_EPOCH=1700000000
ENV CARGO_INCREMENTAL=0 \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}
WORKDIR /build

# Cargo.lock pins every crates.io source and checksum. The patched Chromium
# driver is copied from this repository rather than resolved from the network.
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY bindings ./bindings
COPY vendor/headless_chrome ./vendor/headless_chrome
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    test "$(rustc --version | cut -d' ' -f2)" = "${RUST_VERSION}" && \
    cargo build --release --locked --package basecrawl-core --bin basecrawl

FROM ghcr.io/puppeteer/puppeteer:24.37.2@sha256:59818936eb9768ba3c1681441ec62e8aacaa67c074e2573bd66bf78a065b31e1

ARG SOURCE_DATE_EPOCH=1700000000
ARG CHROMIUM_VERSION=145.0.7632.46
ENV CHROMIUM_VERSION=${CHROMIUM_VERSION} \
    CHROME=/home/pptruser/.cache/puppeteer/chrome/linux-145.0.7632.46/chrome-linux64/chrome \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

COPY --from=build --chown=10042:10042 /build/target/release/basecrawl /usr/local/bin/basecrawl

USER 10042
WORKDIR /home/pptruser
ENTRYPOINT ["/usr/local/bin/basecrawl"]
CMD ["--help"]
