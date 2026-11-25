# syntax=docker/dockerfile:1

# The image of hodor-cert-manager-issuer alone: cert-manager's outside
# issuer, which signs the approved requests for an authority through the
# tenant's certificate authority in Hodor. It runs in the clusters of the
# meshes, apart from Hodor, so it has an image of its own and carries
# nothing else. See docs/operations/hodor-cert-manager-issuer.md.

FROM rust:1.98-bookworm AS build
WORKDIR /src
COPY . .
# As in the Dockerfile of Hodor: the target directory is a cache shared by
# every build on the machine, so the workspace's own files are touched and
# only the dependencies come from the cache.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    find . -path ./target -prune -o -type f -exec touch {} + \
    && cargo build --release --locked --package hodor-cert-manager-issuer --bin hodor-cert-manager-issuer \
    && mkdir /out \
    && cp target/release/hodor-cert-manager-issuer /out/

# Distroless: no shell, no package manager, runs as a non-root user, and
# ships the CA certificates that outbound TLS relies on.
FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/hodor-cert-manager-issuer /usr/local/bin/hodor-cert-manager-issuer
USER nonroot:nonroot
EXPOSE 9090
ENV HODOR_OPS_ADDR=0.0.0.0:9090 \
    HODOR_CERT_MANAGER_ISSUER_CONFIG=/etc/hodor-cert-manager-issuer/config.json
ENTRYPOINT ["/usr/local/bin/hodor-cert-manager-issuer"]
