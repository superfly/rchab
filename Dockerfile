FROM golang:1.16 as build

ARG BUILD_SHA

WORKDIR /app

COPY dockerproxy .

RUN GOOS=linux GARCH=amd64 CGO_ENABLED=0 go build -o dockerproxy -ldflags "-X main.gitSha=$BUILD_SHA -X main.buildTime=$(date +'%Y-%m-%dT%TZ')"

FROM docker:20

RUN apk add bash ip6tables

COPY etc/docker/daemon.json /etc/docker/daemon.json

COPY --from=build /app/dockerproxy /dockerproxy

COPY ./entrypoint ./entrypoint
COPY ./docker-entrypoint.d/* ./docker-entrypoint.d/

ENTRYPOINT ["./entrypoint"]

CMD ["/dockerproxy"]