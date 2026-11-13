# POS/POI management-UI HTTP mocks

Live-captured HTML identity for Nerva's `pos-poi-management-exposed`
finding (ENG-9060). Hardware is out of scope. Ports bind to `127.0.0.1`.

| Service | MODE | Bind | Expect finding | Live source |
| --- | --- | --- | --- | --- |
| Verifone VHQ | `verifone` | `127.0.0.1:18081` | yes | https://vhq.connect.verifone.com/VHQ.Authentication.VHQFederationV1/Account/Login (`<title>VHQ</title>`) |
| Ingenico Estate Manager | `ingenico-estate` | `127.0.0.1:18082` | yes | https://mcmemuat.roamdata.com/emgui/resetPassword.jsp (`<title>Ingenico Estate Management</title>`) |
| Generic Hello | `generic` | `127.0.0.1:18083` | no | — |
| Ingenico TMS | `ingenico-tms` | `127.0.0.1:18084` | yes | https://tmsweb.services.ingenico.co.uk/extranet/login.sm (`<title>TMS Web Access- Login</title>`) |

Nerva probes `/VHQ.Authentication.VHQFederationV1/Account/Login` and
`/emgui/resetPassword.jsp`. TMS identity is on GET `/` and
`/extranet/login.sm`.

Not in this fixture (unverified / guessed — detector also ignores them):
`VeriFone Commander` title, `Configuration Client` title, `Ingenico Telium`
title, `The Estate Manager` as a `<title>`, product `Server` tokens.

## Manual run

```bash
docker compose -f testdata/pos-poi/docker-compose.yml up -d --build

curl -s http://127.0.0.1:18081/VHQ.Authentication.VHQFederationV1/Account/Login | grep -o '<title>[^<]*</title>'
# <title>VHQ</title>
curl -s http://127.0.0.1:18082/emgui/resetPassword.jsp | grep -o '<title>[^<]*</title>'
# <title>Ingenico Estate Management</title>
curl -s http://127.0.0.1:18084/extranet/login.sm | grep -o '<title>[^<]*</title>'
# <title>TMS Web Access- Login</title>

./nerva --misconfigs --json -t 127.0.0.1:18081,127.0.0.1:18082,127.0.0.1:18083,127.0.0.1:18084

docker compose -f testdata/pos-poi/docker-compose.yml down
```
