FROM oven/bun:1.3.10 AS frontend
WORKDIR /app/ui
COPY ui/package.json ui/bun.lock ./
RUN bun install --frozen-lockfile
COPY ui/ ./
RUN bun run build

FROM rust:1.94.0-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends libssl-dev pkg-config && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
COPY --from=frontend /app/ui/dist ./ui/dist
RUN cargo build --locked --release --bins

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates libssl3 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/maxio /usr/local/bin/maxio
COPY --from=builder /app/target/release/maxio-sync /usr/local/bin/maxio-sync
COPY --from=builder /app/target/release/maxio-workspace /usr/local/bin/maxio-workspace
COPY --from=builder /app/target/release/maxio-agent /usr/local/bin/maxio-agent
ENV MAXIO_DATA_DIR="/data"
EXPOSE 9000
VOLUME ["/data"]
ENTRYPOINT ["maxio"]
