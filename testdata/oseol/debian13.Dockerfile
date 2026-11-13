# Honest Debian 13 (Trixie), current stable. Vendor-supported through ~2030.
FROM debian:13

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
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
