# Build static binary using musl
FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev

WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src ./src

RUN cargo build --release --target x86_64-unknown-linux-musl

# Minimal runtime image from scratch
FROM scratch

COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/stverify /stverify

ENTRYPOINT ["/stverify"]
