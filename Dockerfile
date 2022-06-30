FROM golang:1.17 as build

ARG BUILD_SHA

WORKDIR /app

COPY dockerproxy .

RUN GOOS=linux GARCH=amd64 CGO_ENABLED=0 go build -o dockerproxy -ldflags "-X main.gitSha=$BUILD_SHA -X main.buildTime=$(date +'%Y-%m-%dT%TZ')"

FROM docker/buildx-bin:v0.8 as buildx
FROM docker:20.10.12-alpine3.15

RUN apk add bash ip6tables pigz sysstat procps lsof util-linux-misc xz curl sudo rsync

RUN curl -L https://github.com/DarthSim/hivemind/releases/download/v1.0.6/hivemind-v1.0.6-linux-amd64.gz -o hivemind.gz \
  && gunzip hivemind.gz \
  && mv hivemind /usr/local/bin \
  && chmod 755 /usr/local/bin/hivemind

# Required for Nix to function as root
ENV USER root
COPY create_nix_users.sh /create_nix_users.sh
RUN /create_nix_users.sh

# Install Nix
RUN sh <(curl -L https://nixos.org/nix/install) --no-daemon

RUN ln -s /root/.nix-profile/etc/profile.d/nix.sh /etc/profile.d/nix.sh

COPY etc/docker/daemon.json /etc/docker/daemon.json

COPY --from=build /app/dockerproxy /dockerproxy
COPY --from=buildx /buildx /usr/libexec/docker/cli-plugins/docker-buildx

COPY ./entrypoint ./entrypoint
COPY ./docker-entrypoint.d/* ./docker-entrypoint.d/

COPY Procfile ./Procfile
COPY rsyncd.conf /etc/rsyncd.conf

ENV DOCKER_TMPDIR=/data/docker/tmp

ENTRYPOINT ["./entrypoint"]

CMD ["./dockerproxy"]
