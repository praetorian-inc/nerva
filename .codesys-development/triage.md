# Phase 2: Triage - CODESYS Plugin

## Classification

**Work Type:** LARGE (New plugin)
**Classified At:** 2026-02-05T01:19:14Z
**Method:** Signal parsing from user request

## Rationale

| Signal | Evidence |
|--------|----------|
| New plugin from scratch | User: "Create a new Nerva (fingerprintx) plugin for detecting exposed CODESYS PLC programming interfaces" |
| Multiple protocol versions | V2 (little-endian, big-endian) + V3 protocols require separate handshake logic |
| Full detection strategy | Protocol research provided but architecture design still needed |
| Version extraction | Extract runtime version, device name, vendor information, OS type/name |
| Complex implementation | Expected 5+ files: plugin code, types registration, tests, version extraction logic |

## Phases to Execute

All 16 phases will execute (no skips for LARGE work type):

```
1. Setup ✅
2. Triage ✅
3. Codebase Discovery → NEXT
4. Skill Discovery
5. Complexity Assessment
6. Brainstorming
7. Architecture Plan
8. Implementation
9. Design Verification
10. Domain Compliance
11. Code Quality Review
12. Test Planning
13. Testing
14. Coverage Verification
15. Test Quality
16. Completion
```

## Human Approval Checkpoints

| Phase | Type | Description |
|-------|------|-------------|
| 6 | Human approval | Protocol design review after brainstorming |
| 7 | Human approval | Architecture plan review |
| 8 | Human approval | Implementation review |
| 16 | Human approval | Completion review and PR creation |

## Protocol-Specific Considerations

**CODESYS V2 Protocol (TCP/2455, TCP/1217, TCP/1200):**
- Little-endian handshake: `\xbb\xbb\x01\x00\x00\x00\x01`
- Big-endian handshake: `\xbb\xbb\x01\x00\x00\x01\x01`
- Response validation: starts with `0xbb`
- Version extraction: null-terminated strings at specific byte offsets

**CODESYS V3 Protocol (TCP/11740):**
- TCP header magic: `0xe8170100`
- Services layer protocol_id: `0xcd55` (unencrypted)
- Service group `0x01`, service_id `0x04` for device info

## Safety Requirements

As an ICS/PLC protocol plugin, CODESYS must follow strict safety requirements:

- ✅ Read-only detection probes
- ✅ No write operations to PLC memory
- ✅ Handle malformed responses gracefully
- ✅ Proper timeout handling to avoid hanging on unresponsive devices

## Next Steps

Proceeding to **Phase 3: Codebase Discovery** to explore existing plugin patterns and identify reusable code.
