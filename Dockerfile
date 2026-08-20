FROM alpine:latest AS build

RUN apk add --no-cache cmake g++ make curl-dev

WORKDIR /src
COPY CMakeLists.txt ./
COPY src ./src

# Board tuning flags, e.g. --build-arg MIKRODOH_TUNE="-mcpu=cortex-a15".
# Leave empty for portable images: the flags are per-SoC, not per-architecture.
ARG MIKRODOH_TUNE=""

RUN cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DMIKRODOH_TUNE="$MIKRODOH_TUNE" \
    && cmake --build build -j "$(nproc)"

FROM alpine:latest

RUN apk add --no-cache libcurl libstdc++ ca-certificates

COPY --from=build /src/build/mikrodoh /usr/local/bin/mikrodoh

EXPOSE 53/udp 53/tcp
ENTRYPOINT ["/usr/local/bin/mikrodoh"]
