# Honest Ubuntu 16.04 LTS (Xenial). Standard support ended 2021-04-30.
# Apache Server stays Apache/2.4.18 (Ubuntu); OpenSSH is OpenSSH_7.2p2 Ubuntu-*.
FROM ubuntu:16.04

ENV DEBIAN_FRONTEND=noninteractive

RUN printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99no-check-valid-until \
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
