---
name: Bug report
about: wpawolf produced wrong, missing, or corrupt output
title: "[bug] "
labels: bug
---

## What happened

<!-- Exact command you ran and what you expected vs what happened. -->

```
$ wpawolf ...
```

## Expected behaviour

<!-- One paragraph. Reference the FR-* ID from `ARCHITECTURE.md` §8 if relevant. -->

## Minimal reproducing pcap

<!-- Attach a redacted pcap < 1 MiB if possible. Real ESSIDs / MACs must be
scrubbed unless the capture is lab-owned. If you cannot share the capture,
describe what it contains: AKM, # of APs / STAs, # of handshakes, capture
tool. -->

## Environment

- wpawolf version: `wpawolf --version`
- OS + arch:
- Rust toolchain: `rustc --version`
- Install method: source / release binary / package manager

## hcxpcapngtool comparison (if relevant)

<!-- If this is a "wpawolf missed a hash that hcxpcapngtool found" report,
paste both outputs. If this is a "wpawolf emitted a hash hcxpcapngtool
didn't", paste both — note that 'wpawolf ⊇ hcxpcapngtool' is the design
goal, so the superset alone is not a bug. -->
