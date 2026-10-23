#!/bin/sh
set -e
mkdir -p /var/run/sshd
ssh-keygen -A >/dev/null 2>&1 || true
/usr/sbin/sshd
exec /usr/sbin/httpd -D FOREGROUND
