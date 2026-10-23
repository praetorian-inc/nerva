# Oracle DB unauth / auth / TNS-only test fixture

TNS listeners for validating Nerva's `oracle-no-auth` finding (ENG-9054).

Oracle Database has no documented analog of Elasticsearch
`xpack.security.enabled=false` or PostgreSQL `trust`: a network session
always goes through TNS, then a logon, and modern Oracle rejects empty
passwords (`ORA-28218`). A vendor image therefore cannot express the
emit case. This fixture speaks the published TNS/SQL*Net packet layout
(Wireshark `packet-tns`, SQL*Net Connect/Accept/Refuse/Data) and three
postures that match the ticket, without replaying any detector probe.

| Host port | MODE            | TNS Connect to SID `XE` / `ORCL` / `FREEPDB1` | Empty/absent logon                         | Finding ID        |
|-----------|-----------------|-----------------------------------------------|--------------------------------------------|-------------------|
| 15211     | `no-auth`       | Accept                                        | Phase-1 `AUTH_SESSKEY` challenge, then phase-2 session (`AUTH_SESSION_ID`) | `oracle-no-auth`  |
| 15212     | `auth-required` | Accept                                        | Phase-1 `AUTH_SESSKEY` challenge, then `ORA-01017` on phase-2 | (must not emit)   |
| 15213     | `tns-only`      | Refuse `ORA-12514` (no registered services)   | No DB session is possible                  | (must not emit)   |

Unknown `SERVICE_NAME` / `SID` values are refused with `ORA-12514` on
every mode, the same way a stock listener answers a name it does not
know. Ports bind to `127.0.0.1` only.

Refuse packets carry `(VSNNUM=352321536)` (21.0.0.0.0), `(ERR=12514)`,
and `ERROR_STACK=` so a TNS fingerprinter can identify the listener
without a database session.

## Why not a vendor image

| Product setting | Empty-credential DB session? |
|-----------------|------------------------------|
| `gvenzl/oracle-free` / `oracle-xe` with `ORACLE_PASSWORD` | No. Logon with empty credentials → `ORA-01017`. Good auth-required analog, cannot express the emit case. |
| `CREATE USER … IDENTIFIED BY ""` | Rejected (`ORA-28218` / `ORA-00988`) on 11g+. |
| `REMOTE_OS_AUTHENT=TRUE` | OS authentication, not empty credentials. Removed/ignored on current releases. |
| Listener with no services (`tnslsnr` only) | TNS-only analog. This fixture's `tns-only` mode. |

`no-auth` is the PostgreSQL `POSTGRES_HOST_AUTH_METHOD=trust` analog:
any completed logon establishes a session. Phase-1 PreAuth always
returns the O5LOGON `AUTH_SESSKEY` challenge in both `no-auth` and
`auth-required`; only phase-2 (`AUTH_PASSWORD`) returns
`AUTH_SESSION_ID` (no-auth) or `ORA-01017` (auth-required). A detector
must not treat the challenge as a session. The fixture does not
re-implement O5LOGON crypto, so it does not try to tell an encrypted
empty password from a real one. A detector is expected to probe with
empty or absent credentials; this target answers the three postures.

## Known services

`XE`, `XEPDB1`, `ORCL`, `ORCLPDB1`, `FREE`, `FREEPDB1`.

A detector that only Connects with a non-existent `SERVICE_NAME` will
see `ORA-12514` on all three ports (listener fingerprint only). To
reach a DB session it must Connect to a name in that list.

`COMMAND=version` and `COMMAND=status` return a `TNSLSNR for Linux:
Version 21.0.0.0.0` banner. Status on `tns-only` reports no services.

## Manual run

```bash
docker compose -f testdata/oracledb/docker-compose.yml up -d --build

# TNS-only: Refuse 12514 even for SID XE
# auth-required: Accept XE, AUTH_SESSKEY on phase-1, ORA-01017 on phase-2
# no-auth: Accept XE, AUTH_SESSKEY on phase-1, AUTH_SESSION_ID on phase-2

./nerva --misconfigs --json -t 127.0.0.1:15211,127.0.0.1:15212,127.0.0.1:15213

docker compose -f testdata/oracledb/docker-compose.yml down
```

Expected Nerva result:

- `127.0.0.1:15211` emits `oracle-no-auth`
- `127.0.0.1:15212` fingerprints Oracle TNS and does **not** emit `oracle-no-auth`
- `127.0.0.1:15213` fingerprints Oracle TNS and does **not** emit `oracle-no-auth`

## Protocol self-test (no Docker, no Nerva)

```bash
go test -count=1 ./testdata/oracledb/
```

After `docker compose up`, the same tests can hit the mapped ports:

```bash
ORACLEDB_DOCKER=1 go test -count=1 ./testdata/oracledb/ -run TestDockerComposePostures
```

The tests drive TNS Connect / Accept / Refuse / Data from the published
packet layout. They do not import the oracledb plugin.

## Discriminating cases (ENG-9054)

1. **Emit:** database session succeeds with empty or absent credentials
   → `15211` / `MODE=no-auth`.
2. **Do not emit (auth required):** listener is fingerprinted, empty
   logon is rejected → `15212` / `MODE=auth-required`.
3. **Do not emit (TNS only):** listener answers, no DB session →
   `15213` / `MODE=tns-only`.

Sources:

- Wireshark `epan/dissectors/packet-tns.c` (Connect/Accept/Refuse/Data,
  SQL*Net function ids, OCI logon ids)
- SQL*Net refuse descriptor `(DESCRIPTION=(TMP=)(VSNNUM=…)(ERR=12514)(ERROR_STACK=…))`
- Ticket analog: `postgresql-no-auth` / `mysql-no-auth` (empty/anonymous
  login, not default passwords)
