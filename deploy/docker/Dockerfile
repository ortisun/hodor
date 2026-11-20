# syntax=docker/dockerfile:1

# One image with the three binaries. The entrypoint is the server; the
# worker and the CLI are run by overriding the command.

FROM rust:1.98-bookworm AS build
WORKDIR /src
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --release --locked \
        --bin hodor-server --bin hodor-worker --bin hodor-cli \
    && mkdir /out \
    && cp target/release/hodor-server target/release/hodor-worker target/release/hodor-cli /out/

# Distroless: no shell, no package manager, runs as a non-root user, and
# ships the CA certificates that outbound TLS relies on.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/ /usr/local/bin/
USER nonroot:nonroot
EXPOSE 8080 9090
ENV HODOR_LISTEN_ADDR=0.0.0.0:8080 \
    HODOR_OPS_ADDR=0.0.0.0:9090
ENTRYPOINT ["/usr/local/bin/hodor-server"]
