# AI-Driven CI/CD Security Guardrail
# Multi-stage build keeps the runtime image small and runs as a non-root user.

FROM python:3.12-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends gcc && rm -rf /var/lib/apt/lists/*

# Create an isolated virtual environment
RUN python -m venv /opt/guardrail-venv
ENV PATH="/opt/guardrail-venv/bin:$PATH"

# Copy project metadata and source, then install
COPY requirements.txt pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .

FROM python:3.12-slim AS runtime

LABEL org.opencontainers.image.title="AI-Driven CI/CD Security Guardrail"
LABEL org.opencontainers.image.description="AI-Driven CI/CD Guardrail for context-aware secure coding across languages"
LABEL org.opencontainers.image.authors="Sam Degnan <samueladegnan@gmail.com>"
LABEL org.opencontainers.image.source="https://github.com/samueladegnan/ai-cicd-security-guardrail"
LABEL org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV GUARDRAIL_LLM_PROVIDER=mock

WORKDIR /app

# Copy only the virtual environment from the builder stage
COPY --from=builder /opt/guardrail-venv /opt/guardrail-venv
ENV PATH="/opt/guardrail-venv/bin:$PATH"

# Create a non-root user for security.
RUN groupadd --system guardrail && \
    useradd --system --gid guardrail --create-home --home-dir /home/guardrail guardrail && \
    chown -R guardrail:guardrail /app

# Run as the non-root guardrail user.
USER guardrail:guardrail

ENTRYPOINT ["guardrail"]
CMD ["--help"]
