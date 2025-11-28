##############################
# Build the libFuzzer target #
##############################
FROM gcr.io/oss-fuzz-base/base-builder AS builder

WORKDIR /src/mini-crs
COPY . .

# Mimic the typical OSS-Fuzz toolchain locally.
ENV CC=clang \
    CXX=clang++ \
    CFLAGS="-O1 -fno-omit-frame-pointer -g -fsanitize=address" \
    CXXFLAGS="-O1 -fno-omit-frame-pointer -g -fsanitize=address" \
    LIB_FUZZING_ENGINE="-fsanitize=fuzzer" \
    OUT=/out

RUN mkdir -p "${OUT}" && ./build.sh

##############################
# Runtime container          #
##############################
FROM debian:12-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends libstdc++6 ca-certificates \
  && rm -rf /var/lib/apt/lists/*

# Copy the built fuzzer
COPY --from=builder /out/vuln_fuzzer /usr/local/bin/vuln_fuzzer

WORKDIR /workspace
RUN mkdir -p /workspace/corpus
VOLUME ["/workspace/corpus"]

# Default corpus location can be overridden: `docker run ... /tmp/my_corpus`
ENTRYPOINT ["/usr/local/bin/vuln_fuzzer"]
CMD ["/workspace/corpus"]
