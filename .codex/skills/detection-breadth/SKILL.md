---
name: detection-breadth
description: When and how to reach for the companion detectors -- bandit (Python SAST) and trivy (deps + secrets + IaC misconfig) -- alongside the core semgrep/CodeQL/osv/trufflehog toolchain
---

The core Detect toolchain is semgrep (broad SAST), CodeQL (dataflow SAST), osv-scanner (SCA), trufflehog (secrets), and program-analysis (AST/taint/SMT). Two companion servers widen coverage; reach for them deliberately, not reflexively.

- **`bandit_scan`** (mantis_bandit): Python-specific SAST. Use it on Python targets in addition to semgrep -- bandit encodes Python-idiom checks (e.g. `subprocess` with `shell=True`, weak crypto, `yaml.load`, flask debug) that a generic ruleset can under-cover. Every hit is a `candidate`; bandit's own severity/confidence describe rule confidence, not demonstrated impact, so do not report them as final severity. Default `confidence` to `low` for full recall on a first sweep.
- **`trivy_scan`** (mantis_trivy): composition analysis in one pass -- vulnerable dependencies, embedded secrets, and IaC (Dockerfile/Terraform/k8s) misconfigurations. Use it to add container/IaC coverage that osv-scanner (deps only) and trufflehog (secrets only) don't reach. A vulnerable dependency being present does not mean its vulnerable code path is reachable -- that's a separate question for the reachability stage. Secret values are never returned, only rule/line references.

Both degrade gracefully: if the underlying binary isn't installed they report `available: false`. When that happens, say so explicitly rather than claiming coverage you didn't get, and fall back to the core toolchain. Do not double-count: if trivy and osv-scanner both flag the same advisory for the same package, it's one candidate, not two.

Every result from either tool is a `candidate` in the findings lifecycle -- register it via `mantis_findings` `finding_create`, then trace reachability and attacker-simulate before it can become `confirmed` (see the `mantis-pipeline` and `findings-spine` skills).
