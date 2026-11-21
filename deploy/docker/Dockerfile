# syntax=docker/dockerfile:1

# One image with the three binaries and the hosted pages. The entrypoint is
# the server; the worker and the CLI are run by overriding the command.

# The hosted pages: static files built once, the same for every tenant.
FROM node:24-bookworm-slim AS pages
WORKDIR /src/frontend
COPY frontend/auth-ui/package.json frontend/auth-ui/package-lock.json auth-ui/
RUN --mount=type=cache,target=/root/.npm \
    cd auth-ui && npm ci --ignore-scripts --no-audit --no-fund
COPY frontend/auth-ui auth-ui
RUN cd auth-ui && npm run build

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
COPY --from=pages /src/frontend/auth-ui/dist/ /usr/share/hodor/auth-ui/
USER nonroot:nonroot
EXPOSE 8080 9090
ENV HODOR_LISTEN_ADDR=0.0.0.0:8080 \
    HODOR_OPS_ADDR=0.0.0.0:9090 \
    HODOR_PAGES_DIRECTORY=/usr/share/hodor/auth-ui
ENTRYPOINT ["/usr/local/bin/hodor-server"]
