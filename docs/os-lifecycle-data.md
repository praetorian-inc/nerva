# OS security-support data

Nerva embeds `pkg/plugins/oseol/data/lifecycle.json`. It does **not** query a lifecycle service while scanning. Identification rules stay in Go; release dates live only in this generated snapshot. Unknown dates/releases produce no EOL verdict, but identified OS versions can still be recorded as inventory.

## Identification and assessment

- `products.go` is the reviewed product registry: canonical CPE identities, explicit aliases, bounded banner patterns, release normalization, lifecycle-feed mappings, and device-scope guards. Patterns extract version tokens instead of enumerating supported releases. Windows Server years and R revisions are version-independent.
- `identify.go` parses structured CPEs before considering banner/package evidence. A package heuristic cannot override a different explicit OS CPE. Conflicting explicit releases suppress a verdict; an unmapped explicit OS CPE cannot fall back to an IIS guess. Unknown releases remain inventory without an EOL claim.
- `windows.go` only translates IIS/NTLM evidence into candidate OS releases. Those stable protocol mappings are not lifecycle dates and are not a separate Windows EOL implementation. Unknown or conflicting versions yield no candidate; ambiguous evidence never invents a single OS CPE.
- `assessment.go` applies the same all-candidates-known-and-expired rule and finding formatter to every OS. Direct identification supplies one candidate; ambiguous protocol evidence supplies several. The legacy RDP helper delegates to this evaluator and retains its existing severity rules.
- Banner matching uses Go's bounded, linear-time regex engine on at most 4 KiB per evidence string. The registry scales with product grammars, not the number of releases. Weekly refreshes update lifecycle facts only, not executable detection patterns.

## Weekly, review-only refresh

`.github/workflows/refresh-os-lifecycle.yml` runs every Monday at **06:17 UTC**, and supports manual dispatch on `main`. It:

1. Tests the updater using offline fixtures.
2. Downloads all configured endoflife.date v1 feeds, validating product identity, support-phase labels, dates, duplicates, and preservation of existing releases/dates.
3. Atomically replaces the snapshot only after every feed succeeds. A failed fetch or validation leaves the previous file unchanged and fails the workflow.
4. Tests the embedded data and scanner consumers.
5. Commits **only the snapshot** to `automation/refresh-os-lifecycle` and opens/updates a PR targeting `main`.

There is **no direct push to main, automatic approval, merge, or auto-merge step**. Enable GitHub Actions' permission to create pull requests in repository settings. Protect `main` with required human review/status checks; workflow YAML alone cannot restrict every other actor with repository write access. The workflow does not change repository protections.

The default `GITHUB_TOKEN` may not trigger other workflows from its generated PR. The refresh job performs targeted validation before creating the PR; maintainers must run any required checks before merging. Do not bypass protection or give the updater approval/merge privileges to work around this.

No-op refreshes retain the prior timestamp and do not produce timestamp-only PRs. `refreshed_at` means the last **changed** snapshot, not the last successful polling attempt; workflow history records unchanged successful checks. Releases disappearing or losing a known date require manual investigation, not silent deletion. Changed dates and newly published releases become reviewable diffs.

Run locally with Python 3.10+ (standard library only):

```sh
python3 -m unittest discover -s scripts -p 'test_update_lifecycle.py'
python3 scripts/update_lifecycle.py
GOWORK=off go test ./pkg/plugins/oseol -count=1
```

Merging a snapshot PR does **not** change existing binaries or containers. Publish a Nerva release/commit and update/rebuild Guard's pinned images through the normal reviewed deployment process.

## Source review and selected semantics

Reviewed November 10, 2026. The machine-readable transport is `https://endoflife.date/api/v1/products/<product>`. It is a secondary aggregator, not the vendor. Each product records its feed, official documentation URL, and the expected support-phase label. Reviewers should compare changed dates against the vendor's documentation. The updater verifies feed structure/meaning; it does not claim to independently reconcile every vendor website on each run.

Only `eolFrom` is imported. Neither `eoasFrom` (often end of feature/mainstream support) nor `eoesFrom` (paid/optional extension) is a substitute. Null cutoffs remain unknown. Cutoffs are treated conservatively as the final supported calendar day; findings begin the following UTC day.

| Existing coverage / feed | Vendor documentation reviewed | Selected security-support boundary |
| --- | --- | --- |
| Ubuntu / `ubuntu` | [Canonical release cycle](https://ubuntu.com/about/release-cycle) | Standard maintenance and security support, not Ubuntu Pro/ESM or Legacy add-on. Do not use the hardware-maintenance field. |
| Debian / `debian` | [Debian releases and lifecycle table](https://www.debian.org/releases/) | End of Debian LTS, not the earlier Security Team handoff and not commercial ELTS. Coverage of individual architectures/packages can be narrower. |
| RHEL / `rhel` | [Red Hat lifecycle policy](https://access.redhat.com/support/policy/updates/errata) | End of major-release Maintenance Support; not Full Support, EUS/ELCP/ELS, or Long-Life add-ons. Minor-release and entitlement-specific support is not inferred. |
| CentOS Linux / `centos` | [CentOS Linux EOL](https://www.centos.org/centos-linux-eol/) | End of security updates, not the later removal from mirrors. |
| CentOS Stream / `centos-stream` | [CentOS Stream](https://www.centos.org/centos-stream/) | Its own security-support dates. Never reuse CentOS Linux/RHEL dates. |
| Fedora / `fedora` | [Fedora lifecycle](https://docs.fedoraproject.org/en-US/releases/lifecycle/), [structured-source presentation](https://endoflife.date/fedora) | Published per-release EOL, not a calculated fixed lifespan. The official site returned an anti-bot challenge during review; the aggregator and its API were accessible. |
| FreeBSD / `freebsd` | [Supported releases](https://www.freebsd.org/security/), [unsupported releases](https://www.freebsd.org/security/unsupported/) | The exact minor-release security branch, not its longer-lived major branch. Vendor review exposed errors in the previous hand-maintained historical table (for example FreeBSD 6.0). |
| Windows Server / `windows-server` | [Microsoft Fixed Lifecycle](https://learn.microsoft.com/en-us/lifecycle/policies/fixed), [Server 2012](https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2012), [Server 2003 R2](https://learn.microsoft.com/en-us/lifecycle/products/windows-server-2003-r2) | Ordinary Extended Support includes security updates; paid ESU is excluded. For banners without service-pack information, use the latest cutoff across that release's service packs rather than declaring the whole OS EOL at RTM's earlier deadline. R2/SAC/edition families stay distinct; Server 2003 R2 explicitly shares the Server 2003 lifecycle. |
| Legacy Windows client inference / `windows` | [Microsoft version-number mapping](https://learn.microsoft.com/en-us/windows/win32/sysinfo/operating-system-version), [Fixed Lifecycle](https://learn.microsoft.com/en-us/lifecycle/policies/fixed) | IIS/NTLM evidence identifies candidate sets, not one SKU. Every candidate needs a known cutoff; use the latest one. Windows 2000 and Server 2003-family bounds are shared with their server lifecycle. The legacy RDP plugin now gates its existing severity/identification rules on the same refreshed dates rather than treating membership in an old-version list as permanent proof. Do not infer EOL from IIS 10/NT 10 alone. |
| Cisco IOS XE / `cisco-ios-xe` | [Lifecycle policy](https://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/ios-xe-16/bulletin-c25-2378701.html), [17.9 bulletin](https://www.cisco.com/c/en/us/products/collateral/ios-nx-os-software/ios-xe-17/ios-xe-17-9-x-eol.html) | **End of Vulnerability/Security Support**, not end-of-sale, end of software maintenance, or last TAC support. Preserve the existing positive router/switch evidence requirement and AP exclusion. New feeds do not establish device-specific exceptions. |

## Other major OS families and existing inventory-only products

These sources were also assessed. This change refreshes existing detection coverage; it does not add new OS-identification rules or silently broaden EOL verdicts.

| Family | Official reference | Decision / caveat |
| --- | --- | --- |
| Alpine | [Release branches](https://alpinelinux.org/releases/) | `main` and `community` have different support windows; one date is not a promise for every package. Detector integration is not part of this refresh. |
| Amazon Linux | [AL2023 release cadence](https://docs.aws.amazon.com/linux/al2023/ug/release-cadence.html) | Include maintenance/security phase, not just standard support. Non-core packages have separate lifecycles. |
| Rocky Linux | [Releases](https://docs.rockylinux.org/releases/) | Security dates are per major release; only the latest minor release is supported. Do not turn `.elN` into a Rocky identification. |
| AlmaLinux | [Release notes](https://wiki.almalinux.org/release-notes/) | Major security window differs from active support; each minor is superseded by the next. |
| Oracle Linux | [Support policy and linked lifecycle PDF](https://www.oracle.com/linux/support/) | Distinguish Basic/Premier, Extended, and Sustaining Support; `.elN` alone cannot distinguish Oracle from RHEL/rebuilds. |
| SUSE Linux Enterprise | [Lifecycle](https://www.suse.com/lifecycle/) | General, LTSS, and extended support are distinct and service-pack-specific. No entitlement inference from banners. |
| openSUSE | [Lifetime](https://en.opensuse.org/Lifetime) | Direct page returned HTTP 403 during review; structured feed exposes Leap release dates. Tumbleweed rolling support must not be assigned a Leap cutoff. Not enabled. |
| macOS | [Apple security releases](https://support.apple.com/en-us/100100) | Apple lists security releases, not a guaranteed fixed EOL schedule. Do not manufacture dates from the last update or assume a permanent “latest three versions” contract. Not enabled. |
| OpenBSD | [Stable branches](https://www.openbsd.org/stable.html), [errata](https://www.openbsd.org/errata.html) | Support is release/branch-based; do not infer a future EOL date merely from historical release cadence. |
| NetBSD | [Supported releases](https://www.netbsd.org/releases/) | Official support is defined by the currently supported series; an unknown future date remains unknown. |
| Cisco ASA / FTD | [Cisco FTD EOL notices](https://www.cisco.com/c/en/us/products/security/firepower-ngfw/eos-eol-notice-listing.html) | Remain inventory-only: no reviewed structured software-security lifecycle feed was available. Hardware retirement, ASDM versions, and IOS XE cutoffs must not be substituted. Cisco's old ASA listing redirected to a generic security page. |

## Attribution

Generated dates are derived from [endoflife.date](https://endoflife.date/) and its [v1 API](https://endoflife.date/docs/api/), with adaptations for Windows service-pack families. The upstream repository is MIT licensed; its notice is retained in `pkg/plugins/oseol/data/LICENSE.endoflife-date`. Official vendor pages remain the authority for support policy and exceptions. Source/API availability and a valid schema are not proof that a date is correct: human review remains required.
