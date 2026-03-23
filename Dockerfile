FROM rust:1-bookworm AS builder

RUN apt-get update && apt-get install -y musl-tools && rm -rf /var/lib/apt/lists/*
RUN rustup target add x86_64-unknown-linux-musl

WORKDIR /build

# Copy commons (sibling directory — CI checks it out, local dev has it adjacent)
COPY commons/ /commons/

# Copy transit source
COPY transit/ /build/

RUN cargo build --release --target x86_64-unknown-linux-musl \
    --bin keyva-transit \
    --bin keyva-transit-cli

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/keyva-transit /keyva-transit
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/keyva-transit-cli /keyva-transit-cli

USER nonroot:nonroot
EXPOSE 6399 8099

ENTRYPOINT ["/keyva-transit"]
