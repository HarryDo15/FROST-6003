FROM rust:1.90-slim AS crypto
WORKDIR /build
COPY rust/frost_bridge/ ./
RUN cargo build --release --locked

FROM python:3.12-slim AS builder
WORKDIR /app
RUN pip install --no-cache-dir uv==0.13.6
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev --no-cache --compile-bytecode

FROM python:3.12-slim
ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
RUN useradd --uid 10001 --create-home --shell /usr/sbin/nologin vault
COPY --from=builder /app/.venv /app/.venv
COPY --from=crypto /build/target/release/frost-bridge /usr/local/bin/frost-bridge
COPY group_vault ./group_vault
USER vault
EXPOSE 8080
CMD ["python", "-m", "group_vault.coordinator", "--config", "/config/coordinator.json", "--host", "0.0.0.0"]
