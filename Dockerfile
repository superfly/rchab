FROM golang:1.16 as build

WORKDIR /app

ENV GO111MODULE=on
# COPY dockerproxy/go.mod go.mod
# COPY dockerproxy/go.sum go.sum

# RUN go mod download

COPY dockerproxy .

RUN go build -o dockerproxy

FROM ubuntu:bionic

RUN apt-get update && apt-get install --no-install-recommends -y \
    ca-certificates curl sudo bash git \
    net-tools dnsutils iproute2 \
    apt-transport-https gnupg-agent software-properties-common \
    && apt autoremove -y

RUN apt-get install --no-install-recommends -y iptables libdevmapper1.02.1 \
    && curl https://download.docker.com/linux/ubuntu/dists/bionic/pool/stable/amd64/containerd.io_1.3.7-1_amd64.deb --output containerd.deb \
    && dpkg -i containerd.deb \
    && rm containerd.deb \
    && curl https://download.docker.com/linux/ubuntu/dists/bionic/pool/stable/amd64/docker-ce-cli_19.03.12~3-0~ubuntu-bionic_amd64.deb --output docker-cli.deb \
    && dpkg -i docker-cli.deb \
    && rm docker-cli.deb \
    && curl https://download.docker.com/linux/ubuntu/dists/bionic/pool/stable/amd64/docker-ce_19.03.13~3-0~ubuntu-bionic_amd64.deb --output docker.deb \
    && dpkg -i docker.deb \
    && rm docker.deb \
    && curl -L "https://github.com/docker/compose/releases/download/1.27.4/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose \
    && chmod +x usr/local/bin/docker-compose

COPY etc/docker/daemon.json /etc/docker/daemon.json

COPY --from=build /app/dockerproxy /dockerproxy

COPY ./entrypoint ./entrypoint
COPY ./docker-entrypoint.d/* ./docker-entrypoint.d/

ENTRYPOINT ["./entrypoint"]

CMD ["/dockerproxy"]