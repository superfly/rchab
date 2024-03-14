FROM golang:1.21 as build

ARG BUILD_SHA

WORKDIR /app

COPY dockerproxy .

RUN GOOS=linux GARCH=amd64 CGO_ENABLED=0 go build -o dockerproxy -ldflags "-X main.gitSha=$BUILD_SHA -X main.buildTime=$(date +'%Y-%m-%dT%TZ')"

FROM docker/buildx-bin:v0.8 as buildx
FROM docker:20

RUN apk add bash ip6tables pigz sysstat procps lsof util-linux-misc xz curl sudo

COPY etc/docker/daemon.json /etc/docker/daemon.json

COPY --from=build /app/dockerproxy /dockerproxy
COPY --from=buildx /buildx /usr/libexec/docker/cli-plugins/docker-buildx

COPY ./entrypoint ./entrypoint
COPY ./docker-entrypoint.d/* ./docker-entrypoint.d/

ENV DOCKER_TMPDIR=/data/docker/tmp

ENTRYPOINT ["./entrypoint"]

CMD ["./dockerproxy"]
