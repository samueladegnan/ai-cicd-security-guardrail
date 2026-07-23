# AI-Driven CI/CD Security Guardrail
# Multi-stage build keeps the runtime image small and secure.

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

LABEL maintainer="Your Name <you@example.com>"
LABEL description="AI-Driven CI/CD Guardrail for secure C/C++ coding"

WORKDIR /workspace

# Copy only the virtual environment from the builder stage
COPY --from=builder /opt/guardrail-venv /opt/guardrail-venv
ENV PATH="/opt/guardrail-venv/bin:$PATH"

# Default to the mock provider so the image is runnable without API keys
ENV GUARDRAIL_LLM_PROVIDER=mock

ENTRYPOINT ["guardrail"]
CMD ["--help"]
