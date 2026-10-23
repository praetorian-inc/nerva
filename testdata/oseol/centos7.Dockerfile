# Honest CentOS 7 (vendor EOL 2024-06-30). httpd + OpenSSH from this image's packages.
# Vault mirrors: CentOS 7 mirrors were retired after EOL.
FROM centos:7

RUN sed -i 's/mirrorlist/#mirrorlist/g' /etc/yum.repos.d/CentOS-*.repo \
    && sed -i 's|#baseurl=http://mirror.centos.org|baseurl=http://vault.centos.org|g' /etc/yum.repos.d/CentOS-*.repo \
    && yum install -y httpd openssh-server \
    && yum clean all \
    && printf '%s\n' \
         'ServerTokens OS' \
         'ServerSignature On' \
         'ServerName localhost' \
         > /etc/httpd/conf.d/banner.conf

COPY entrypoint-centos.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80 22
CMD ["/entrypoint.sh"]
