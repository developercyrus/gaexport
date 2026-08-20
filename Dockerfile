# The CLI plus `gaexport serve` — for self-hosting the server-side decoder.
#
# Prefer the static build (Dockerfile.web / GitHub Pages) when exposing this to
# other people: in server mode the export is uploaded to *this* container, and
# whoever runs it can see the secrets. Server mode is meant for your own machine
# or a private, TLS-terminated host you control.
FROM rust:1-bookworm AS build
WORKDIR /src
# Prime the dependency cache before copying the sources.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs \
    && echo '' > src/lib.rs \
    && cargo build --release --locked 2>/dev/null || true
COPY . .
RUN touch src/main.rs src/lib.rs && cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --create-home gaexport
COPY --from=build /src/target/release/gaexport /usr/local/bin/gaexport
USER 10001
EXPOSE 8765
ENV GAEXPORT_TOKEN=""
# A token is mandatory for non-loopback binds; pass one via GAEXPORT_TOKEN.
ENTRYPOINT ["/usr/local/bin/gaexport"]
CMD ["serve", "--host", "0.0.0.0", "--port", "8765", "--allow-remote", "--idle-timeout", "0"]
