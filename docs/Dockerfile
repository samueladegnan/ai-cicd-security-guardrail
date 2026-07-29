# Jekyll site for AI CI/CD Security Guardrail portfolio
# Usage (from docs/):
#   docker compose up --build
#   or
#   docker build -t guardrail-docs .
#   docker run --rm -p 4000:4000 -v "${PWD}:/srv/jekyll" guardrail-docs

FROM ruby:3.2-slim-bookworm

WORKDIR /srv/jekyll

# Install build dependencies needed by native gems (nokogiri, ffi, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy only the Gemfile; the host Gemfile.lock was generated on a different
# Ruby/Bundler combo and can fail on Ruby 3.2 (e.g. strscan/rexml mismatch).
# Let Bundler resolve a fresh lockfile inside the image.
COPY Gemfile ./

RUN bundle install --jobs 4 --retry 3

EXPOSE 4000

# Serve the site. Remove any stale host-side lockfile so Bundler uses the
# gems already installed in the image, not a lockfile generated for a
# different Ruby/Bundler combination.
CMD ["sh", "-c", "rm -f Gemfile.lock && bundle exec jekyll serve --host 0.0.0.0 --port 4000 --force_polling"]
