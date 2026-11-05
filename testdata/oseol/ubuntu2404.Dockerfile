# Honest Ubuntu 24.04 LTS (Noble). Standard security maintenance until May 2029.
FROM ubuntu:24.04

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
