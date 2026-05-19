# Operations Guide

## CI

- Run `go test ./...` as the main correctness gate.
- Run `go test ./cmd/k8doc -run TestPublishedOutputContract` to guard the JSON output contract.
- Run `go test ./cmd/k8doc -run 'TestComposeReportUpgradeReadinessIncludesManifest'` to keep the upgrade-readiness manifest advisory contract stable.
- Run `go test ./internal/diagnostics -run 'Test(PagedList|ListPodsCached|CollectCapabilityPreflight|TransientError|IssuePolicy)'` to validate runtime guardrails and signal policy.
- Run `go test ./internal/diagnostics -run 'TestEvaluateManifestUpgradeReadiness|TestExtractManifestLineValues'` when changing manifest scanning or Helm template handling.
- Run `go test ./internal/diagnostics -run '^$' -bench 'Benchmark(PagedList|ListPodsCached|NormalizeIssues)' -benchmem` to record runtime regression metrics.

## Releases

- Push a semantic tag such as `v1.2.3` to trigger `./.github/workflows/release.yml`.
- The release workflow reruns the repository test, output-contract, and runtime-guardrail gates before publishing artifacts.
- Published GitHub Release assets include platform-specific raw binaries, packaged archives, and `checksums.txt`.
- Tags containing `-alpha`, `-beta`, or `-rc` are published as prereleases automatically.

## In-Cluster

- For operator or support use, prefer downloading a published release binary from GitHub Releases instead of building from source on the target host.
- Apply one of the RBAC profiles in `deploy/rbac/` depending on scope.
- Run with `--output json` for machine-readable artifact collection.
- For pre-upgrade validation, pair `--mode upgrade-readiness --target-k8s-version vX.Y` with repo manifests from `deploy/`, `manifests/`, `k8s/`, `charts/`, or `helm/`, or override the scan set explicitly with `--manifest-paths`.
- Use `--enable-active-probes` and `--enable-host-network-probes` only when the execution environment is allowed to reach API-proxy or host-network targets.

## Upgrade Readiness

- `upgrade-readiness` now combines cluster-side deprecated API usage with repo-side manifest scanning against the target Kubernetes version.
- Manifest scanning understands literal YAML/JSON, common Helm inline branches, helper templates resolved through `define`, `include`, `template`, and `tpl(include ...)`, and emits a separate warning when template logic still needs manual review.
- Treat `Manifest Template Resolution Uncertainty` as a manual follow-up queue: render the chart for the target version or inspect helper logic before declaring the upgrade path clear.

## Status Semantics

- `partial`: the check or section produced usable output but one or more required operations failed.
- `skipped`: the check was blocked by RBAC or policy and could not run normally.
- `not-applicable`: the check does not make sense for the selected scope, such as namespace-only execution for cluster-wide observability scans.

## Runtime Guardrails

- `--list-chunk-size` and `--max-list-items` control memory usage for large inventories.
- `--max-concurrent-checks` and `--max-concurrent-requests` cap API pressure.
- `--retry-attempts`, `--retry-backoff-ms`, and `--slow-operation-threshold-ms` help detect regressions in transient failure handling and latency.