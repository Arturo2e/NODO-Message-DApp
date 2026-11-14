FROM rust:1.99.0-bookworm AS relay-builder

WORKDIR /workspace/server
COPY server/Cargo.toml server/Cargo.lock ./
COPY server/src ./src
RUN cargo fetch --locked
COPY migrations /workspace/migrations
RUN cargo build --locked --release

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=relay-builder /workspace/server/target/release/nodo-relay /usr/local/bin/nodo-relay
COPY dist/public /app/dist/public

ENV PORT=3000
ENV WEB_ROOT=/app/dist/public
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/nodo-relay"]
