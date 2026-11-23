# syntax=docker/dockerfile:1

# One image with the three binaries, the hosted pages, the admin console
# and the opa binary the worker checks policies with. The entrypoint is
# the server; the worker and the CLI are run by overriding the command.

# The hosted pages and the admin console: static files built once, the
# same for every tenant. The console reads the compiled theme from the
# hosted pages, so both are built in one stage.
FROM node:24-bookworm-slim AS pages
WORKDIR /src/frontend
COPY frontend/auth-ui/package.json frontend/auth-ui/package-lock.json auth-ui/
COPY frontend/admin-console/package.json frontend/admin-console/package-lock.json admin-console/
RUN --mount=type=cache,target=/root/.npm \
    cd auth-ui && npm ci --ignore-scripts --no-audit --no-fund \
    && cd ../admin-console && npm ci --ignore-scripts --no-audit --no-fund
COPY frontend/auth-ui auth-ui
COPY frontend/admin-console admin-console
RUN cd auth-ui && npm run build && cd ../admin-console && npm run build

# The opa binary the worker checks, tests and simulates policies with
# (Decision 0026). The static image holds the release binary; the stage
# below refuses it unless it is the published file for the architecture.
FROM openpolicyagent/opa:1.10.1-static@sha256:e1f196b5316301785d5251543c9d0f3f6c83ce6ac23263b494730427fa80e248 AS opa

# The build image, already pulled for the build below, has sha256sum.
FROM rust:1.98-bookworm AS opa-checked
ARG TARGETARCH
COPY --from=opa /opa /opa
RUN case "$TARGETARCH" in \
        amd64) expected=43b1efa7e81425456dbb8d82c0256b6dbe69c934e5c4a1cb71dc65715ac4b35d ;; \
        arm64) expected=3b77a28ec99dcf7d98ec014ab4773bd1f9ad0340faee7b8ae811cbb8baa9f5bf ;; \
        *) echo "no opa checksum for $TARGETARCH" >&2; exit 1 ;; \
    esac \
    && echo "$expected  /opa" | sha256sum --check --strict

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
COPY --from=opa-checked /opa /usr/local/bin/opa
COPY --from=pages /src/frontend/auth-ui/dist/ /usr/share/hodor/auth-ui/
COPY --from=pages /src/frontend/admin-console/dist/ /usr/share/hodor/admin-console/
USER nonroot:nonroot
EXPOSE 8080 9090
ENV HODOR_LISTEN_ADDR=0.0.0.0:8080 \
    HODOR_OPS_ADDR=0.0.0.0:9090 \
    HODOR_PAGES_DIRECTORY=/usr/share/hodor/auth-ui \
    HODOR_CONSOLE_DIRECTORY=/usr/share/hodor/admin-console \
    HODOR_OPEN_POLICY_AGENT_BINARY=/usr/local/bin/opa
ENTRYPOINT ["/usr/local/bin/hodor-server"]
