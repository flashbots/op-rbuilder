FROM rust:1.85 AS builder

WORKDIR /app

ARG BINARY="tdx-quote-provider"
ARG FEATURES

COPY . .

RUN cargo build --release --features="$FEATURES" --package=${BINARY}

FROM gcr.io/distroless/cc-debian12
WORKDIR /app

ARG BINARY="tdx-quote-provider"
COPY --from=builder /app/target/release/${BINARY} /usr/local/bin/

ENTRYPOINT ["/usr/local/bin/tdx-quote-provider"]
