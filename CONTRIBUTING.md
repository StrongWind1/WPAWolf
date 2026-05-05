# Contributing to wpawolf

Thanks for wanting to contribute. `wpawolf` is a narrow-scope tool (WPA/WPA2/WPA3-FT-PSK handshake extraction) with a strict correctness bar: the project exists because upstream `hcxpcapngtool` silently drops valid handshakes, and any regression that puts us back in the "silently drops" column is the worst possible kind of bug.

## Before you write code

1. Read [`ARCHITECTURE.md`](ARCHITECTURE.md) end-to-end. Pay particular attention to §2 (the eleven hash categories), §3 (5-phase pipeline), §4 (critical invariants), and §8 (FR-* wire-level requirements -- find the ID your change relates to).
2. Skim [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md) for the `WPA*01*` -- `WPA*11*` line format your output must match, and [`HASHCAT-CURRENT-FORMATS.md`](HASHCAT-CURRENT-FORMATS.md) §8 for the verified per-category hashcat support matrix.

## Repository layout

```
wpawolf/
├── src/                          Rust source (input/, link/, ieee80211/, store/, pair/, output/)
├── tests/                        Integration tests + binary fixtures (incl. tests/fixtures/generated/ corpus)
├── tools/fixturegen/             Workspace crate that emits the test-capture corpus (separate Cargo crate)
├── .github/                      CI / Security / Release workflows + issue + PR templates
├── README.md                     Project intro + CLI / usage reference
├── ARCHITECTURE.md               Why everything is the way it is: pipeline, invariants, design decisions
├── CHANGELOG.md                  Released-version summary and milestone history
├── CONTRIBUTING.md               How to set up, lint, test, and submit a patch (this file)
├── HASHCAT-CURRENT-FORMATS.md    Current hashcat WPA formats (modes 22000 + 37100) and how the eleven categories map onto them today
├── HASHCAT-NEW-FORMATS.md        The eleven hash categories: per-category cracker math, line layout, message-pair byte spec, design rationale
├── HASHCAT-PROPOSED-CHANGES.md   Sketch of two new hashcat modes (22002 passphrase + 22003 PMK-direct) that consume all eleven categories
├── Cargo.toml                    Workspace + crate config + strict lint policy
└── Makefile                      Developer workflow + cross-platform release builds
```

The project runs strict clippy (pedantic + nursery + cargo) with zero warnings, and the test suite covers 746 cases across lib + binary + integration. An external multi-GB regression dataset (out-of-tree) is exercised opportunistically before each release on real-world traffic that is too noisy or legally encumbered to commit.

## Before you open a PR

```sh
make check-all
make check-parity   # only when touching pairing / output / extraction
```

`make check-all` runs, in order: `fmt`, `clippy` (zero warnings), `cargo deny`, `cargo check`, `cargo test`, `cargo doc` with warnings-as-errors, ASCII hygiene, LF hygiene, and unused-dependency detection. A green `check-all` is required for review.

`make check-parity` re-runs the superset test against `hcxpcapngtool` with `CI=true` set, which converts a missing or stale oracle from a soft skip into a hard failure. Run this whenever you change anything in `src/pair/`, `src/output/`, `src/store/`, or `src/extract/`.

Install the pre-commit hook so you catch lint failures before push:

```sh
make hooks
```

### Parity oracle: hcxpcapngtool >= 7.0.1

The superset test in `tests/integration/superset_test.rs` requires `hcxpcapngtool >= 7.0.1` on `PATH`. Distro packages (Ubuntu 22.04/24.04, Debian stable) ship 6.2.x and emit a pre-7.0.1 hash-line format that is not a valid parity reference for current wpawolf. Build from upstream:

```sh
git clone --depth 1 --branch 7.1.2 https://github.com/ZerBea/hcxtools
sudo apt-get install -y libssl-dev libz-dev   # or dnf / brew equivalents
make -C hcxtools hcxpcapngtool
sudo install -m 0755 hcxtools/hcxpcapngtool /usr/local/bin/hcxpcapngtool
hcxpcapngtool --version
```

If hcxpcapngtool is missing or older than 7.0.1, the test prints a clearly-tagged skip notice and the remaining suite still runs (so contributors who only touch unrelated areas don't need the oracle installed). The CI gate panics in either case, so a regression cannot slip through to main.

## Commit messages

- Imperative mood, first line ≤72 chars.
- Conventional prefix where it fits (`feat:`, `fix:`, `refactor:`, `docs:`, `ci:`, `test:`, `chore:`).
- No AI attribution, no emoji.
- The body should describe *what the change does* and *why*, referencing the FR-* / T* IDs involved. A future reader reconstructing intent should be able to do so from the message alone.

## Dependency additions

Require a paragraph-long justification in the PR body addressing the rejected-crate policy in [`ARCHITECTURE.md §4`](ARCHITECTURE.md). Bar is high: target runtime dep count is 2 (`flate2`, `clap`). Dev-dependencies are less restrictive but still subject to `cargo deny` licence allow-list.

## Adding a capture fixture

- Under 1 MiB, commit to `tests/fixtures/pcaps/`.
- Over 1 MiB, keep out-of-tree and reference it from benchmarks only.
- **Redact** real ESSIDs and client MAC addresses unless the capture comes from a lab network you control. wireshark's *Edit → Preferences → Name Resolution* + `editcap` can help.

The companion crate at [`tools/fixturegen/`](tools/fixturegen/) emits a deterministic 75-fixture pcap/pcapng corpus covering every (hash category × PMKID site × N#E# combo × link-layer × edge case) tuple, with cryptographically valid PMK / PMKID / MIC values — 117 of 123 lines crack end-to-end through hashcat 7.1.2 with PSK `hashcat!` (the 6 that don't are documented hashcat kernel limitations, see [`HASHCAT-CURRENT-FORMATS.md`](HASHCAT-CURRENT-FORMATS.md) §8.1).

## Reporting hashcat / hcxtools gaps

New findings about upstream bugs land as a regression test in `tests/integration/` with a comment that names the upstream issue / PR. Cite the relevant `ARCHITECTURE.md §` if the finding is referenced from production code; otherwise the test is its own documentation.

## Authorized use

All contributions must be framed for authorized defensive / research use. Do not submit features that capture traffic, inject frames, or otherwise move this tool out of the "offline pcap analysis" lane.
