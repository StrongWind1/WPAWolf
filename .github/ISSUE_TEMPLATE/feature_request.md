---
name: Feature request
about: Propose new functionality
title: "[feat] "
labels: enhancement
---

## Problem

<!-- What is missing? One paragraph. If this relates to a documented upstream
gap (e.g. an `hcxpcapngtool` divergence), cite the upstream source line. -->

## Proposed solution

<!-- How should wpawolf behave? Map onto the module layout in
`ARCHITECTURE.md` §3 (the 5-phase pipeline) and propose which FR-*
requirement (`ARCHITECTURE.md` §8) this corresponds to. -->

## Scope check

- [ ] This stays within "offline pcap analysis" (no capture, no injection).
- [ ] This is in-scope per `ARCHITECTURE.md` §1 (WPA/WPA2/WPA3-FT-PSK only;
      no SAE/OWE/EAP-TLS/WEP).
- [ ] No new crate dependency *or* the dep is justified per
      CONTRIBUTING.md (`flate2` and `clap` are the entire runtime budget).

## Alternatives considered

<!-- What else did you look at? Why is this the right shape? -->
