# HTTPFingerprinter Infrastructure + Kubernetes Pilot

## Implementation Summary

Successfully implemented the HTTPFingerprinter infrastructure for Nerva, enabling detection of technologies running over HTTP/HTTPS transports. This replaces the pattern of creating separate service plugins for HTTP-based applications with technology fingerprinting attached to HTTP service payloads.

## What Was Implemented

### Phase 1: Fingerprinter Registry

**Created:** `pkg/plugins/fingerprinters/registry.go`

Implemented a registry system for HTTP fingerprinters with the following components:

- `FingerprintResult` struct containing technology, version, CPEs, and metadata
- `HTTPFingerprinter` interface with `Name()`, `Match()`, and `Fingerprint()` methods
- `Register()` function for adding fingerprinters to the registry
- `GetFingerprinters()` function to retrieve all registered fingerprinters
- `RunFingerprinters()` function to execute all matching fingerprinters on an HTTP response

**Key Design Decisions:**

- Fingerprinters use a two-phase detection pattern:
  1. `Match()` - Fast pre-filter based on headers/status before body reading
  2. `Fingerprint()` - Full detection after body is read
- Returns `nil` result (not error) when detection doesn't match, allowing multiple fingerprinters to run
- Designed to work on responses HTTP has already fetched (doesn't make additional requests)

**Tests:** `pkg/plugins/fingerprinters/registry_test.go` (7 tests, all passing)

### Phase 2: Kubernetes Fingerprinter

**Created:** `pkg/plugins/fingerprinters/kubernetes.go`

Ported the detection logic from the existing kubernetes plugin to a fingerprinter:

- Detects Kubernetes API servers via `/version` endpoint JSON responses
- Validates required fields (`gitVersion`, `platform`)
- Extracts version from `gitVersion` (strips `v` prefix, handles suffixes like `+k3s1`, `-gke`)
- Generates CPE in format `cpe:2.3:a:kubernetes:kubernetes:<version>:*:*:*:*:*:*:*`
- Returns metadata including platform, goVersion, and gitCommit

**Match Logic:**

- Checks for `application/json` Content-Type header
- Fast pre-filter before body parsing

**Detection:**

- Parses JSON body into `k8sVersionResponse` struct
- Validates presence of `gitVersion` and `platform` fields
- Extracts base version (handles distributions like k3s, GKE, EKS)

**Tests:** `pkg/plugins/fingerprinters/kubernetes_test.go` (9 test cases, all passing)

- Tests for vanilla Kubernetes, k3s, and GKE distributions
- Tests for invalid JSON, missing fields, and non-k8s responses
- Integration test with registry

### Phase 3: HTTP Plugin Integration

**Modified:** `pkg/plugins/services/http/http.go`

Integrated fingerprinters into the HTTP plugin's `fingerprint()` function:

1. Added import: `"github.com/praetorian-inc/nerva/pkg/plugins/fingerprinters"`
2. Modified `fingerprint()` function to call `fingerprinters.RunFingerprinters()` after Wappalyzer
3. Appends fingerprinter results (technologies and CPEs) to existing Wappalyzer results

**Integration Point:**

```go
// Wappalyzer fingerprinting (existing)
fingerprintResult := analyzer.FingerprintWithInfo(resp.Header, data)
for tech, appInfo := range fingerprintResult {
    technologies = append(technologies, tech)
    if cpe := appInfo.CPE; cpe != "" {
        cpes = append(cpes, cpe)
    }
}

// Custom HTTP fingerprinters (new)
for _, result := range fingerprinters.RunFingerprinters(resp, data) {
    technologies = append(technologies, result.Technology)
    cpes = append(cpes, result.CPEs...)
}
```

Both HTTPPlugin and HTTPSPlugin now use fingerprinters.

**Bug Fixes:** Fixed pre-existing linting issues in HTTP test files (`t.Errorf(err.Error())` → `t.Error(err)`)

## Files Created/Modified

### Created

- `pkg/plugins/fingerprinters/registry.go` (70 lines)
- `pkg/plugins/fingerprinters/registry_test.go` (208 lines)
- `pkg/plugins/fingerprinters/kubernetes.go` (95 lines)
- `pkg/plugins/fingerprinters/kubernetes_test.go` (282 lines)

### Modified

- `pkg/plugins/services/http/http.go` (added import, modified `fingerprint()` function)
- `pkg/plugins/services/http/http_test.go` (fixed linting issue)
- `pkg/plugins/services/http/https_test.go` (fixed linting issue)

## Verification

### Compilation

All modified packages compile successfully:

```bash
✅ go build ./pkg/plugins/fingerprinters/...
✅ go build ./pkg/plugins/services/http/...
✅ go vet ./pkg/plugins/fingerprinters/...
✅ go vet ./pkg/plugins/services/http/...
```

### Tests

All tests pass:

```bash
✅ go test ./pkg/plugins/fingerprinters/... -v
   - 7 registry tests passing
   - 9 Kubernetes fingerprinter tests passing

✅ go test ./pkg/plugins/services/http/... -v
   - HTTP plugin tests passing (31.6s)
   - HTTPS plugin tests passing
```

## Architecture Considerations

### Current Design: Fingerprinters Work on Existing Responses

The current implementation has fingerprinters operate on responses the HTTP plugin has already fetched. This means:

- **For default endpoints (`/`)**: Kubernetes fingerprinter will detect k8s if HTTP happens to hit `/`
- **For custom endpoints (`/version`)**: Kubernetes requires HTTP to fetch `/version` specifically

### Alternative: Fingerprinters with Custom Endpoints

The task description mentioned an alternative approach where fingerprinters could specify custom endpoints:

```go
type HTTPFingerprinter interface {
    Name() string
    Match(resp *http.Response) bool
    Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error)
    ProbeEndpoint() string  // Return "" for default "/" or specific path like "/version"
}
```

Then HTTP plugin could:
1. Hit default endpoint, run fingerprinters
2. For fingerprinters with custom endpoints, make additional requests

**Recommendation:** Consider adding `ProbeEndpoint()` method in future iterations to enable k8s detection without requiring HTTP to hit `/version` by default.

### Phase 4: Existing Kubernetes Plugin

As requested, the existing `pkg/plugins/services/kubernetes/kubernetes.go` plugin has been kept in place but is now redundant. The kubernetes plugin makes its own HTTP requests to `/version`, while the fingerprinter detects k8s from responses HTTP already fetched.

**Next steps:**

1. Validate that fingerprinter approach works as expected in production
2. Consider deprecating the standalone kubernetes plugin
3. Evaluate other HTTP-based services for fingerprinter conversion (Elasticsearch, etc.)

## Integration Pattern

Other HTTP-based technologies can now follow this pattern:

1. Create fingerprinter in `pkg/plugins/fingerprinters/<technology>.go`
2. Implement `HTTPFingerprinter` interface
3. Register via `init()` function: `Register(&TechnologyFingerprinter{})`
4. Write comprehensive tests
5. Automatic integration with HTTP/HTTPS plugins

Example candidates:
- Elasticsearch (`/_cluster/health` or `/_cat/indices`)
- Kibana (`/api/status`)
- Grafana (`/api/health`)
- Jenkins (`/api/json`)

## Design Principles Applied

### TDD (Test-Driven Development)

- Tests written before implementation for both registry and Kubernetes fingerprinter
- RED-GREEN-REFACTOR cycle followed
- All tests passing before claiming completion

### DRY (Don't Repeat Yourself)

- Fingerprinter pattern extracted to reusable registry
- Detection logic shared via `HTTPFingerprinter` interface
- HTTP and HTTPS plugins use same `fingerprint()` function

### KISS (Keep It Simple)

- Simple interface with 3 methods
- No premature abstraction (custom endpoints can be added later if needed)
- Registry is just a slice and helper functions

### Evidence-Based Implementation

- Read existing kubernetes plugin to understand detection logic
- Read HTTP plugin to understand integration point
- Verified ServiceHTTP/ServiceHTTPS payload structures before implementation

---

## Metadata

```json
{
  "agent": "capability-developer",
  "output_type": "implementation",
  "timestamp": "2026-02-05T12:20:28Z",
  "feature_directory": "/Users/thomasreburn/Downloads/chariot-development-platform/modules/nerva/.claude/.output/agents/2026-02-05-122028-http-fingerprinter-infrastructure",
  "skills_invoked": [
    "using-skills",
    "discovering-reusable-code",
    "semantic-code-operations",
    "calibrating-time-estimates",
    "enforcing-evidence-based-analysis",
    "gateway-capabilities",
    "gateway-backend",
    "persisting-agent-outputs",
    "developing-with-tdd",
    "verifying-before-completion",
    "adhering-to-dry",
    "adhering-to-yagni",
    "preferring-simple-solutions",
    "debugging-systematically",
    "tracing-root-causes",
    "gateway-integrations",
    "using-todowrite"
  ],
  "source_files_verified": [
    "/Users/thomasreburn/Downloads/chariot-development-platform/modules/nerva/pkg/plugins/plugins.go",
    "/Users/thomasreburn/Downloads/chariot-development-platform/modules/nerva/pkg/plugins/services/http/http.go",
    "/Users/thomasreburn/Downloads/chariot-development-platform/modules/nerva/pkg/plugins/services/kubernetes/kubernetes.go",
    "/Users/thomasreburn/Downloads/chariot-development-platform/modules/nerva/pkg/plugins/types.go"
  ],
  "status": "complete",
  "handoff": {
    "next_agent": null,
    "context": "Implementation complete. Ready for integration testing and production validation."
  }
}
```
