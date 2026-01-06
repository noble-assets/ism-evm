FROM rust:1.92-bookworm AS builder
RUN apt-get update && apt-get install -y protobuf-compiler && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . .
RUN cargo build --release --bin prover-service

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/prover-service /usr/local/bin/

EXPOSE 50051
ENTRYPOINT ["prover-service"]