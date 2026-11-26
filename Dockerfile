FROM rust:1-bookworm AS builder
WORKDIR /app

# Copy the single-crate Rust project and embedded agent skill.
COPY Cargo.toml Cargo.lock build.rs ./
COPY agent ./agent
COPY src ./src
RUN cargo build --release --locked --bin brokenapp

FROM debian:bookworm-slim

# Chromium is required at runtime (BrokenApp crawls via CDP).
RUN apt-get update && apt-get install -y --no-install-recommends \
    chromium \
    ca-certificates \
    fonts-liberation \
  && rm -rf /var/lib/apt/lists/* \
  && useradd --create-home --shell /bin/sh brokenapp

# Container-safe Chromium defaults.
ENV BROKENAPP_NO_SANDBOX=1
ENV BROKENAPP_CHROME_ARGS="--disable-dev-shm-usage"

COPY --from=builder /app/target/release/brokenapp /usr/local/bin/brokenapp

USER brokenapp
WORKDIR /home/brokenapp

ENTRYPOINT ["brokenapp"]
CMD ["--help"]
