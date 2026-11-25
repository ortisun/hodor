# syntax=docker/dockerfile:1

# The image of hodor-ext-authz alone: Envoy's external authorization over
# gRPC, answered by Hodor's Authorization API. It runs in the mesh next to
# the proxies, apart from Hodor, so it has an image of its own and carries
# nothing else. See docs/operations/hodor-ext-authz.md.

FROM rust:1.98-bookworm AS build
WORKDIR /src
COPY . .
# As in the Dockerfile of Hodor: the target directory is a cache shared by
# every build on the machine, so the workspace's own files are touched and
# only the dependencies come from the cache.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    find . -path ./target -prune -o -type f -exec touch {} + \
    && cargo build --release --locked --package hodor-ext-authz --bin hodor-ext-authz \
    && mkdir /out \
    && cp target/release/hodor-ext-authz /out/

# Distroless: no shell, no package manager, runs as a non-root user, and
# ships the CA certificates that outbound TLS relies on.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/hodor-ext-authz /usr/local/bin/hodor-ext-authz
USER nonroot:nonroot
EXPOSE 9191 9090
ENV HODOR_EXT_AUTHZ_LISTEN_ADDR=0.0.0.0:9191 \
    HODOR_OPS_ADDR=0.0.0.0:9090 \
    HODOR_EXT_AUTHZ_CONFIG=/etc/hodor-ext-authz/config.json
ENTRYPOINT ["/usr/local/bin/hodor-ext-authz"]
