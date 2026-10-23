# Elasticsearch unauth / auth test fixture

Official Elasticsearch 8.15.3 nodes for validating Nerva's
`elasticsearch-no-auth` finding (ENG-9055).

This fixture does not mock the protocol. It runs Elastic's published
image with the documented security settings:

| Port  | Security                         | GET /                                      | Finding ID              |
|-------|----------------------------------|--------------------------------------------|-------------------------|
| 19200 | `xpack.security.enabled=false`   | HTTP 200, `"tagline": "You Know, for Search"` | `elasticsearch-no-auth` |
| 19201 | `xpack.security.enabled=true`    | HTTP 401, `"type": "security_exception"`   | (must not emit)         |

HTTP TLS is off on both nodes so the probe sees those status codes
instead of a failed handshake. Ports bind to `127.0.0.1` only.

Sources:

- [Install Elasticsearch with Docker](https://www.elastic.co/docs/deploy-manage/deploy/self-managed/install-elasticsearch-docker-basic)
- [Security settings](https://www.elastic.co/guide/en/elasticsearch/reference/8.15/security-settings.html)
- Root API (`GET /`) tagline `"You Know, for Search"` — hardcoded in `MainResponse.toXContent`
  from at least 5.6 through 9.5 (see Version stability)
- Unauthenticated REST with security on: HTTP 401 `security_exception`

## Version stability

8.15.3 is a representative 8.x node, not a version-specific fingerprint.
The finding identifiers do not change across Elasticsearch majors.

| Identifier | 5.x | 6.x | 7.x | 8.x | 9.x | Notes |
|------------|-----|-----|-----|-----|-----|-------|
| `"tagline": "You Know, for Search"` | yes | yes | yes | yes | yes | Hardcoded in `MainResponse`. Unauth 200 match. |
| HTTP 401 + `"type": "security_exception"` | yes (X-Pack) | yes | yes | yes | yes | Auth-required GET /. Present since X-Pack on 5.0. |
| Reason: `missing authentication token for REST request` | yes | yes | early 7 | — | — | 5.0 sample: [elastic/elasticsearch#21399](https://github.com/elastic/elasticsearch/issues/21399) |
| Reason: `missing authentication credentials for REST request` | — | later | yes | yes | yes | 8.15.3 live fixture. Same `security_exception` / 401. |
| `version.build_flavor` | no | yes | yes | yes | yes | Extra field; do not require it. |
| `version.distribution` | no | no | no | no | no | OpenSearch only. |
| Security default | off | off | off | **on** (+ HTTP TLS) | **on** | Unauth 200 is a misconfig on 8+/9+; it was the 7.x default. |

OpenSearch (fork of 7.10) is the important negative: same JSON shape, different
tagline (`"The OpenSearch Project: https://opensearch.org/"`) and
`version.distribution: "opensearch"`. Do not treat that as Elasticsearch.

Do not key the finding on:

- Exact 401 reason text (`token` vs `credentials`)
- `WWW-Authenticate` schemes (5.x Basic only; later ApiKey / Bearer)
- `lucene_version` / `version.number` (change every release)
- `build_flavor` (absent before 6.x)

A 7.17 node with security off produces the same 200 tagline as this 8.15.3
unauth node. A 7.x node with `xpack.security.enabled=true` produces the same
401 `security_exception` class as the auth node. Extra images are not required
for identifier coverage.

## Manual run

Each node wants about 1 GB. Docker Desktop should have ≥4 GB allocated.

```bash
docker compose -f testdata/elasticsearch/docker-compose.yml up -d --wait

curl -s http://127.0.0.1:19200/
# HTTP 200 JSON including "tagline" : "You Know, for Search"

curl -s -D- http://127.0.0.1:19201/
# HTTP 401 JSON including "type" : "security_exception"

./nerva --misconfigs --json -t 127.0.0.1:19200,127.0.0.1:19201

docker compose -f testdata/elasticsearch/docker-compose.yml down
```

Expected Nerva result:

- `127.0.0.1:19200` emits `elasticsearch-no-auth`
- `127.0.0.1:19201` does not emit that ID

## Integration test

```bash
go test -count=1 -timeout 15m -tags integration ./pkg/plugins/services/http \
  -run TestElasticsearch
```

Skipped under `-short`. Requires Docker and a pull of
`docker.elastic.co/elasticsearch/elasticsearch:8.15.3`.
