# Jekyll site for AI CI/CD Security Guardrail portfolio
# Usage (from docs/):
#   docker compose up --build
#   or
#   docker build -t guardrail-docs .
#   docker run --rm -p 4000:4000 -v "${PWD}:/srv/jekyll" guardrail-docs

FROM ruby:3.2-slim-bookworm

WORKDIR /srv/jekyll

# Install build dependencies needed by native gems (nokogiri, ffi, etc.)
ENV BUNDLE_PATH=/usr/local/bundle

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy the dependency lockfile so local and CI builds resolve the same gems.
COPY Gemfile Gemfile.lock ./

# Install outside the mounted source tree so the runtime volume cannot hide it.
ENV BUNDLE_FROZEN=true
RUN bundle config set --local path /usr/local/bundle \
    && bundle install --jobs 4 --retry 3 \
    && bundle check \
    && bundle exec jekyll --version

EXPOSE 4000

# Serve the site using the locked bundle installed in the image.
CMD ["sh", "-c", "bundle exec jekyll serve --host 0.0.0.0 --port 4000 --force_polling"]
