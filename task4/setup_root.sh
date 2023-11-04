#!/bin/sh

curl https://github.com/flounderk.keys >> /root/.ssh/authorized_keys
curl https://github.com/flounderk.keys >> /home/ubuntu/.ssh/authorized_keys

sed -i 's/PasswordAuthentication yes/PasswordAuthentication no/g' /etc/ssh/sshd_config.d/50-cloud-init.conf

sudo apt install -y autoconf dh-autoreconf libcryptsetup-dev

