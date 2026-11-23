# Stage 1: Build static musl binary
FROM rust:alpine AS builder

RUN apk add --no-cache musl-dev binutils
WORKDIR /usr/src/stverify

COPY Cargo.toml Cargo.lock* ./
COPY src ./src

RUN cargo build --release && \
    strip target/release/stverify

# Stage 2: Minimal distroless/scratch runtime
FROM scratch

COPY --from=builder /usr/src/stverify/target/release/stverify /stverify

# Run as unprivileged non-root UID
USER 65532:65532

ENTRYPOINT ["/stverify"]
