# OS end-of-life test fixtures

Official distro images with that release's own `httpd`/`apache2` and
OpenSSH. No banner rewriting. Used to validate Nerva's `os-eol` finding
(ENG-9062).

Ports bind to `127.0.0.1` only. Old images are `platform: linux/amd64`.

| Service | HTTP | SSH | Expect `os-eol` | Why |
| --- | --- | --- | --- | --- |
| CentOS 7 | 18070 | 22070 | HTTP yes | `Apache/2.4.6 (CentOS)` → CentOS 7. Vendor EOL 2024-06-30. |
| Ubuntu 16.04 | 18071 | 22071 | HTTP yes, SSH yes | `Apache/2.4.18 (Ubuntu)` and `OpenSSH_7.2p2 Ubuntu-*`. Standard support ended 2021-04-30. |
| Debian 10 | 18072 | 22072 | HTTP **no**, SSH yes | HTTP `Apache/2.4.x (Debian)` has no `+debN`. SSH banner carries `+deb10`. LTS ended 2024-06-30. |
| Ubuntu 24.04 | 18074 | 22074 | no | Still in standard support (until May 2029). |
| Debian 13 | 18075 | 22075 | no | Current stable. |

Debian HTTP is a deliberate negative: DSA backports change the displayed
Apache patch version, so it is not a release id. Do not map it.

## Sources

- Ubuntu release cycle: https://ubuntu.com/about/release-cycle
- Ubuntu apache2 versions (Server header): https://packages.ubuntu.com/apache2
- Ubuntu openssh versions: https://packages.ubuntu.com/openssh-server
- Debian LTS: https://wiki.debian.org/LTS and https://wiki.debian.org/DebianReleases
- CentOS 7 EOL: https://www.centos.org/centos-linux-eol

## Manual run

```bash
docker compose -f testdata/oseol/docker-compose.yml up -d --wait

curl -sI http://127.0.0.1:18070/ | grep -i server
# Server: Apache/2.4.6 (CentOS)
curl -sI http://127.0.0.1:18071/ | grep -i server
# Server: Apache/2.4.18 (Ubuntu)
nc -v 127.0.0.1 22071 </dev/null
# SSH-2.0-OpenSSH_7.2p2 Ubuntu-…

./nerva --misconfigs --json -t \
  127.0.0.1:18070,127.0.0.1:18071,127.0.0.1:18072,127.0.0.1:18074,127.0.0.1:18075
./nerva --misconfigs --json -t \
  127.0.0.1:22070,127.0.0.1:22071,127.0.0.1:22072,127.0.0.1:22074,127.0.0.1:22075

docker compose -f testdata/oseol/docker-compose.yml down
```

Expected Nerva result:

- HTTP `:18070` and `:18071` emit `os-eol`
- HTTP `:18072` (Debian 10) does **not** emit `os-eol`
- HTTP `:18074` and `:18075` do not emit `os-eol`
- SSH `:22071` and `:22072` emit `os-eol`
- SSH `:22074` and `:22075` do not emit `os-eol`
