FROM golang:1.21 as build

ARG BUILD_SHA

WORKDIR /app

COPY dockerproxy .

RUN GOOS=linux GARCH=amd64 CGO_ENABLED=0 go build -o dockerproxy -ldflags "-X main.gitSha=$BUILD_SHA -X main.buildTime=$(date +'%Y-%m-%dT%TZ')"

FROM docker:24.0.7-alpine3.19

RUN apk add bash iptables-legacy pigz sysstat procps lsof util-linux-misc xz curl sudo \
    && mv /sbin/iptables /sbin/iptables.original \
    && mv /sbin/ip6tables /sbin/ip6tables.original \
    && ln -s /sbin/iptables-legacy /sbin/iptables \
    && ln -s /sbin/ip6tables-legacy /sbin/ip6tables

COPY etc/docker/daemon.json /etc/docker/daemon.json

COPY --from=build /app/dockerproxy /dockerproxy
COPY --from=docker/buildx-bin:v0.12 /buildx /usr/libexec/docker/cli-plugins/docker-buildx

COPY ./entrypoint ./entrypoint
COPY ./docker-entrypoint.d/* ./docker-entrypoint.d/

ENV DOCKER_TMPDIR=/data/docker/tmp

ENTRYPOINT ["./entrypoint"]

CMD ["./dockerproxy"]
