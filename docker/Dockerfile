# Build stage for bob
FROM ubuntu:24.04 AS bob-builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    git \
    libssl-dev \
    uuid-dev \
    libhiredis-dev \
    zlib1g-dev \
    libjsoncpp-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . .

RUN mkdir -p build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make -j$(nproc)

# Pull pre-built kvrocks binary from official image
FROM apache/kvrocks:2.9.0 AS kvrocks-bin

# Runtime stage - standalone with Redis and Kvrocks
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install runtime dependencies, Redis, and supervisor
RUN apt-get update && apt-get install -y \
    libssl3t64 \
    libuuid1 \
    libsnappy1v5 \
    libhiredis1.1.0 \
    libjsoncpp25 \
    ca-certificates \
    wget \
    unzip \
    supervisor \
    redis-server \
    jq \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy built binaries
COPY --from=bob-builder /app/build/bob /app/bob
COPY --from=kvrocks-bin /bin/kvrocks /usr/local/bin/kvrocks

# Create directories for persistent data
RUN mkdir -p /data/redis /data/kvrocks /data/bob /app/logs /etc/kvrocks

# Copy config templates
COPY docker/supervisord.conf /etc/supervisor/conf.d/supervisord.conf
COPY docker/redis.conf /etc/redis/redis.conf
COPY docker/kvrocks.conf /etc/kvrocks/kvrocks.conf
COPY docker/bob.json /app/bob.json
COPY docker/entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# Expose ports
# 21842 - bob server port
# 40420 - REST API port
EXPOSE 21842 40420

# Data volumes for persistence
VOLUME ["/data/redis", "/data/kvrocks", "/data/bob"]

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
