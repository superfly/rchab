FROM ubuntu:bionic

RUN apt-get update && apt-get install --no-install-recommends -y \
    ca-certificates curl sudo openssh-server bash git \
    cron net-tools dnsutils iproute2 \
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

# Add crontab file in the cron directory
COPY crontab /etc/cron.d/crontab

# Give execution rights on the cron job
RUN chmod 0644 /etc/cron.d/crontab \
    && /usr/bin/crontab /etc/cron.d/crontab

# Setup your SSH server daemon, copy pre-generated keys
RUN rm -rf /etc/ssh/ssh_host_*_key*
COPY etc/ssh/sshd_config /etc/ssh/sshd_config

COPY ./entrypoint ./entrypoint
COPY ./docker-entrypoint.d/* ./docker-entrypoint.d/

ENTRYPOINT ["./entrypoint"]

CMD ["/usr/sbin/sshd", "-D"]