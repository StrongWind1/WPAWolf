# Contributing to wpawolf

Thanks for wanting to contribute. `wpawolf` is a narrow-scope tool (WPA/WPA2/
WPA3-FT-PSK handshake extraction) with a strict correctness bar: the project
exists because upstream `hcxpcapngtool` silently drops valid handshakes, and
any regression that puts us back in the "silently drops" column is the worst
possible kind of bug.

## Before you write code

1. Read [`ARCHITECTURE.md`](ARCHITECTURE.md) end-to-end. Pay particular
   attention to §2 (the 11-type hash taxonomy), §3 (5-phase pipeline),
   §4 (critical invariants), and §8 (FR-* wire-level requirements -- find
   the ID your change relates to).
2. Skim [`HASHCAT-NEW-FORMATS.md`](HASHCAT-NEW-FORMATS.md) for the
   `WPA*01*` -- `WPA*11*` taxonomy your output must match, and
   [`HASHCAT-CURRENT-FORMATS.md`](HASHCAT-CURRENT-FORMATS.md) §8 for the
   verified per-type hashcat support matrix.

## Before you open a PR

```sh
make check-all
```

This runs, in order: `fmt`, `clippy` (zero warnings), `cargo deny`,
`cargo check`, `cargo test`, `cargo doc` with warnings-as-errors, ASCII
hygiene, LF hygiene, and unused-dependency detection. A green `check-all` is
required for review.

Install the pre-commit hook so you catch lint failures before push:

```sh
make hooks
```

## Commit messages

- Imperative mood, first line ≤72 chars.
- Conventional prefix where it fits (`feat:`, `fix:`, `refactor:`, `docs:`,
  `ci:`, `test:`, `chore:`).
- No AI attribution, no emoji.
- The body should describe *what the change does* and *why*, referencing the
  FR-* / T* IDs involved. A future reader reconstructing intent should be
  able to do so from the message alone.

## Dependency additions

Require a paragraph-long justification in the PR body addressing the
rejected-crate policy in [`ARCHITECTURE.md §4`](ARCHITECTURE.md). Bar is
high: target runtime dep count is 2 (`flate2`, `clap`). Dev-dependencies
are less restrictive but still subject to `cargo deny` licence allow-list.

## Adding a capture fixture

- Under 1 MiB, commit to `tests/fixtures/pcaps/`.
- Over 1 MiB, keep out-of-tree and reference it from benchmarks only.
- **Redact** real ESSIDs and client MAC addresses unless the capture comes
  from a lab network you control. wireshark's *Edit → Preferences → Name
  Resolution* + `editcap` can help.

## Reporting hashcat / hcxtools gaps

New findings about upstream bugs land as a regression test in
`tests/integration/` with a comment that names the upstream issue / PR.
Cite the relevant `ARCHITECTURE.md §` if the finding is referenced from
production code; otherwise the test is its own documentation.

## Authorised use

All contributions must be framed for authorised defensive / research use.
Do not submit features that capture traffic, inject frames, or otherwise
move this tool out of the "offline pcap analysis" lane.
