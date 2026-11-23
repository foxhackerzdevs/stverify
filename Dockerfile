# Stage 1: Build static musl binary
FROM rust:1.83-alpine AS builder

RUN apk add --no-cache musl-dev
WORKDIR /usr/src/stverify

COPY Cargo.toml Cargo.lock* ./
COPY src ./src

RUN cargo build --release --target x86_64-unknown-linux-musl && \
    strip target/x86_64-unknown-linux-musl/release/stverify

# Stage 2: Minimal distroless/scratch runtime
FROM scratch

COPY --from=builder /usr/src/stverify/target/x86_64-unknown-linux-musl/release/stverify /stverify

# Run as unprivileged non-root UID
USER 65532:65532

ENTRYPOINT ["/stverify"]
