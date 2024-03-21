FROM golang:1.21-alpine AS overlaybd_snapshotter_build
WORKDIR /work
RUN apk add git make
RUN git clone --branch v1.0.4 https://github.com/containerd/accelerated-container-image.git
RUN cd accelerated-container-image \
    && make \
    && make install

FROM alpine:3.19 AS overlaybd_build
WORKDIR /work
RUN apk add bash cmake curl-dev e2fsprogs-dev gcc g++ gflags-dev git gtest-dev make libaio-dev libnl3-dev linux-headers openssl-dev patch pkgconf sudo zlib-dev zstd-dev
RUN git clone https://github.com/superfly/overlaybd \
    && cd overlaybd \
    && git submodule update --init
RUN mkdir -p overlaybd/build \
    && cd overlaybd/build \
    && cmake ..
RUN cd overlaybd/build \
    && make -j$(nproc) \
    && make install

FROM golang:1.21 as dockerproxy_build
WORKDIR /app
COPY dockerproxy .
RUN GOOS=linux GARCH=amd64 CGO_ENABLED=0 go build -o dockerproxy -ldflags "-X main.gitSha=$BUILD_SHA -X main.buildTime=$(date +'%Y-%m-%dT%TZ')"

FROM docker:24.0.7-alpine3.19
ARG BUILD_SHA
RUN apk add bash pigz sysstat procps lsof util-linux-misc xz curl sudo libcurl e2fsprogs e2fsprogs-libs libaio libnl3 libssl3 zlib zstd-libs
COPY etc/docker/daemon.json /etc/docker/daemon.json
COPY --from=dockerproxy_build /app/dockerproxy /dockerproxy
COPY --from=docker/buildx-bin:v0.12 /buildx /usr/libexec/docker/cli-plugins/docker-buildx
COPY --from=overlaybd_snapshotter_build /opt/overlaybd/snapshotter /opt/overlaybd/snapshotter
COPY --from=overlaybd_snapshotter_build /etc/overlaybd-snapshotter /etc/overlaybd-snapshotter
COPY --from=overlaybd_build /opt/overlaybd /opt/overlaybd
COPY --from=overlaybd_build /etc/overlaybd /etc/overlaybd
COPY ./entrypoint ./entrypoint
COPY ./docker-entrypoint.d/* ./docker-entrypoint.d/
ENV DOCKER_TMPDIR=/data/docker/tmp
ENTRYPOINT ["./entrypoint"]
CMD ["./dockerproxy"]
