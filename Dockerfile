# Build stage
FROM rust:1.77-alpine AS builder
WORKDIR /app
RUN apk add --no-cache musl-dev
COPY Cargo.toml Cargo.lock ./
# Create dummy src to cache dependencies
RUN mkdir src && echo "fn main() {}" > src/main.rs && cargo build --release && rm -rf src
COPY src ./src
RUN touch src/main.rs && cargo build --release

# Runtime stage
FROM alpine:latest
WORKDIR /app
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/target/release/rvg-gateway /app/rvg-gateway
ENV PORT=8000
ENV DATA_DIR=/data
EXPOSE $PORT
CMD ["/app/rvg-gateway"]