FROM rust:1-bookworm AS builder

RUN apt-get update && apt-get install -y musl-tools && rm -rf /var/lib/apt/lists/*

WORKDIR /build

COPY commons/ /commons/
COPY transit/ /build/

RUN rustup target add x86_64-unknown-linux-musl

RUN cargo build --release --target x86_64-unknown-linux-musl \
    -p transit-server -p transit-cli

# --- keyva-transit: encryption-as-a-service ---
FROM gcr.io/distroless/static-debian12:nonroot AS keyva-transit
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/keyva-transit /keyva-transit
USER nonroot:nonroot
EXPOSE 6399
ENTRYPOINT ["/keyva-transit"]

# --- keyva-transit-cli: command-line client ---
FROM gcr.io/distroless/static-debian12:nonroot AS keyva-transit-cli
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/keyva-transit-cli /keyva-transit-cli
USER nonroot:nonroot
ENTRYPOINT ["/keyva-transit-cli"]
