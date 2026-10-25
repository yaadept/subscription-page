FROM rust:1-trixie AS backend-build
WORKDIR /opt/app

# Build dependencies first so they are cached until Cargo.toml/Cargo.lock change
COPY backend/Cargo.toml backend/Cargo.lock ./
RUN mkdir src \
    && echo 'fn main() {}' > src/main.rs \
    && touch src/lib.rs \
    && cargo build --release --locked --bin rw-subpage \
    && rm -rf src

COPY backend/src ./src
RUN touch src/main.rs src/lib.rs \
    && cargo build --release --locked --bin rw-subpage

FROM debian:trixie-slim
WORKDIR /opt/app

LABEL org.opencontainers.image.title="Remnawave Subscription Page"
LABEL org.opencontainers.image.description="Remnawave Subscription Page"
LABEL org.opencontainers.image.url="https://github.com/remnawave/subscription-page"
LABEL org.opencontainers.image.source="https://github.com/remnawave/subscription-page"
LABEL org.opencontainers.image.vendor="Remnawave"
LABEL org.opencontainers.image.licenses="AGPL-3.0"
LABEL org.opencontainers.image.documentation="https://docs.rw"

COPY --from=backend-build /opt/app/target/release/rw-subpage /usr/local/bin/rw-subpage
COPY frontend/dist/ ./frontend/

HEALTHCHECK --interval=30s --timeout=3s --start-period=20s --start-interval=2s --retries=3 \
    CMD ["rw-subpage", "--healthcheck"]

USER 65532:65532

ENTRYPOINT ["rw-subpage"]
