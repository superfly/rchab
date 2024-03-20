# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  # Provision /data. In production, the size is hard-coded in web.
  # https://github.com/superfly/web/blob/663d025e29d52567ffb6cbe1b2d8640ac7099e46/app/graphql/mutations/ensure_machine_remote_builder.rb#L87
  config.vm.disk :disk, name: "data", size: '50GB'
  config.vm.provision 'mount_data', type:"shell", inline: <<-SHELL
    set -euo pipefail

    lsblk

    parted /dev/sdb --script mklabel gpt
    parted /dev/sdb --script mkpart primary ext4 0% 100%

    mkfs.ext4 /dev/sdb1

    mkdir /data
    mount /dev/sdb1 /data
  SHELL

  # Host-only network configuration
  config.vm.network "private_network", ip: "192.168.56.10"
  
  # TODO: we probably want to build our own base box here, but that's... work. (tvd, 2022-10-06)
  config.vm.box = "generic/ubuntu1804"
  config.vm.box_version = "4.1.14"

  config.vm.network "forwarded_port", guest: 2375, host: 2375
  config.vm.network "forwarded_port", guest: 8080, host: 8080

  # nfsd disabled UDP by default around 2017, but Vagrant by default uses UDP.
  # http://git.linux-nfs.org/?p=steved/nfs-utils.git;a=commitdiff;h=fbd7623dd8d5e418e7cb369d4026d5368f7c46a6
  # https://developer.hashicorp.com/vagrant/docs/synced-folders/nfs
  config.vm.synced_folder ".", "/home/vagrant/rchab",
    type: "nfs", mount_options: ['local_lock=all'], nfs_udp: false

  config.vm.provider :libvirt do |lv|
    lv.memory = 4096
    lv.cpus = 2
  end

  config.vm.provision "shell", inline: <<-SHELL
    set -eo pipefail
    echo "Provisioning with user: $(whoami)"
    apt update -y

    apt install -y apt-transport-https ca-certificates curl software-properties-common
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
    add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu bionic stable"
    apt-cache policy docker-ce

    apt install -y \
      build-essential \
      dnsutils \
      docker-ce \
      htop \
      iproute2 \
      net-tools \
      ;

    goversion=1.21.5
    wget https://go.dev/dl/go${goversion}.linux-amd64.tar.gz
    echo "e2bc0b3e4b64111ec117295c088bde5f00eeed1567999ff77bc859d7df70078e go${goversion}.linux-amd64.tar.gz" | sha256sum --check
    rm -rf /usr/local/go && tar -C /usr/local -xzf go${goversion}.linux-amd64.tar.gz
    echo 'export PATH=/usr/local/go/bin:$PATH' | tee /etc/profile.d/golang.sh
    /usr/local/go/bin/go version

    adduser vagrant docker

    # level3 failed to resolve some of the go domains when setting this up; use quad9
    sed -i 's/DNS=4.2.2.1 4.2.2.2 208.67.220.220/DNS=9.9.9.9 149.112.112.112/' /etc/systemd/resolved.conf
    systemctl restart systemd-resolved

    # disable docker; we need the software, but we run the service ourselves
    systemctl stop docker
    systemctl stop docker.socket
    systemctl disable docker
    systemctl disable docker.socket
  SHELL
end
