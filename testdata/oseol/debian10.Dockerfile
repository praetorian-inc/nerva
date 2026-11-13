# Honest Debian 10 (Buster). Debian LTS ended 2024-06-30.
# HTTP Server is Apache/2.4.x (Debian) with no +debN tag — not an os-eol HTTP signal.
# OpenSSH banner carries Debian-10+deb10u*, which is the Debian release id.
FROM debian:10

ENV DEBIAN_FRONTEND=noninteractive

RUN printf '%s\n' \
      'deb http://archive.debian.org/debian buster main' \
      'deb http://archive.debian.org/debian-security buster/updates main' \
      > /etc/apt/sources.list \
    && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99no-check-valid-until \
    && apt-get update \
    && apt-get install -y --no-install-recommends apache2 openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && printf '%s\n' \
         'ServerTokens OS' \
         'ServerSignature On' \
         'ServerName localhost' \
         > /etc/apache2/conf-available/banner.conf \
    && a2enconf banner

COPY entrypoint-debian.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 22
CMD ["/entrypoint.sh"]
