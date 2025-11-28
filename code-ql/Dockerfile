FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
ARG CODEQL_ARCHIVE=codeql-bundle.zip

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
     ca-certificates \
     curl \
     clang \
     build-essential \
     python3 \
     unzip \
  && rm -rf /var/lib/apt/lists/*

# Copy and unpack a CodeQL CLI bundle placed next to this Dockerfile.
COPY ${CODEQL_ARCHIVE} /tmp/codeql-bundle.zip
RUN unzip /tmp/codeql-bundle.zip -d /opt \
  && rm /tmp/codeql-bundle.zip

# The extracted bundle lives at /opt/codeql and contains the CLI binary "codeql".
ENV PATH="/opt/codeql:${PATH}"
ENV CODEQL_PACK_ROOT="/opt/codeql/packs"

# Pre-download required query packs (cpp-all includes stdlib and queries).
RUN codeql pack download codeql/cpp-all && codeql pack download codeql/cpp-upgrades

WORKDIR /workspace
COPY . /workspace

# Default to run the CodeQL helper; you can override with docker run <image> <args>
ENTRYPOINT ["bash", "code-ql/run_codeql.sh"]
