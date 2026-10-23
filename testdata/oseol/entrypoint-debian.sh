#!/bin/sh
set -e
mkdir -p /run/sshd /var/run/sshd
ssh-keygen -A >/dev/null 2>&1 || true
/usr/sbin/sshd
exec apache2ctl -D FOREGROUND
