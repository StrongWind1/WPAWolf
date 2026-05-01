.PHONY: fmt fmt-fix lint lint-fix doc dev build check \
        test test-release test-matrix check-parity \
        audit audit-citations machete \
        ascii-check lf-check hygiene \
        build-linux-musl build-linux-arm-musl \
        build-macos-arm build-macos-x86 build-macos-universal \
        build-windows \
        dist size \
        fix hooks clean check-all all

# Default target -- running bare `make` builds dist artifacts for the current platform.
all: dist

CARGO := cargo
DIST  := dist
BIN   := wpawolf

# -- OS / architecture detection -----------------------------------------------
# uname -s: Linux | Darwin | MINGW*/MSYS* (Windows Git Bash)
# uname -m: x86_64 | aarch64 (Linux ARM64) | arm64 (macOS M-series)
UNAME_S := $(shell uname -s 2>/dev/null)
UNAME_M := $(shell uname -m 2>/dev/null)

ifeq ($(findstring Linux,$(UNAME_S)),Linux)
  PLATFORM := linux
else ifeq ($(findstring Darwin,$(UNAME_S)),Darwin)
  PLATFORM := macos
else
  PLATFORM := windows
endif

# Normalise: macOS reports arm64, Linux ARM reports aarch64 -- unify to arm64.
ifneq (,$(filter arm64 aarch64,$(UNAME_M)))
  ARCH := arm64
else
  ARCH := x86_64
endif

# -- Rust target triples --------------------------------------------------------
TARGET_LINUX_X86_MUSL := x86_64-unknown-linux-musl
TARGET_LINUX_ARM_MUSL := aarch64-unknown-linux-musl
TARGET_MACOS_ARM      := aarch64-apple-darwin
TARGET_MACOS_X86      := x86_64-apple-darwin
TARGET_WIN_X86_MSVC   := x86_64-pc-windows-msvc
TARGET_WIN_X86_GNU    := x86_64-pc-windows-gnu
TARGET_WIN_ARM_MSVC   := aarch64-pc-windows-msvc

# -- Formatting ---------------------------------------------------------------

# Fail if any file would change.
fmt:
	$(CARGO) fmt --all -- --check

# Apply in-place.
fmt-fix:
	$(CARGO) fmt --all

# -- Linting ------------------------------------------------------------------

# Lint levels are defined in Cargo.toml [lints.clippy] and clippy.toml.
lint:
	$(CARGO) clippy --all-targets --all-features

lint-fix:
	$(CARGO) clippy --fix --allow-dirty --all-targets --all-features

# -- Documentation ------------------------------------------------------------

# Build docs for the public API; treat rustdoc warnings as errors.
doc:
	RUSTDOCFLAGS="-D warnings" $(CARGO) doc --all-features --no-deps

# -- Build ---------------------------------------------------------------------

# Debug build on the native target -- fastest compile-check.
dev:
	$(CARGO) build --all-features

# Optimised build for the native target. Use before dist to verify locally.
build:
	$(CARGO) build --profile release --all-features

# Fast type-check, no codegen.
check:
	$(CARGO) check --all-targets --all-features

# -- Tests ---------------------------------------------------------------------

# Full test suite (all features). Use for quick local runs.
test:
	$(CARGO) test --all-targets --all-features

# Release-mode test (catches overflow / inlining regressions hidden by debug).
test-release:
	$(CARGO) test --release --all-targets --all-features

# Feature matrix: wpawolf currently exposes no Cargo features, so this is a
# single-configuration run. Kept as a named target so `check-all` matches the
# convention and so adding a feature later only touches the Makefile.
test-matrix: test

# Parity gate: runs the superset test under CI=true so a missing or stale
# hcxpcapngtool oracle is a hard failure instead of a silent skip. wpawolf
# claims parity against hcxpcapngtool >= 7.0.1 -- distro packages are too
# old; build from upstream source first. See README "Parity oracle" section.
check-parity:
	CI=true $(CARGO) test --release --test superset -- --nocapture

# -- Dependency auditing --------------------------------------------------------

audit:
	$(CARGO) deny check

# Verify every [hcxpcapngtool:NNNN] citation in src/ and ARCHITECTURE.md
# points at a real line in the vendored ref/hcxtools/hcxpcapngtool.c.
# Catches drift when the vendored source is updated without re-checking
# the citations that depend on its line numbering.
audit-citations:
	./tools/audit_citations.sh

machete:
	$(CARGO) machete

# -- File hygiene --------------------------------------------------------------

ascii-check:
	@echo "Checking for non-ASCII bytes in tracked source files..."
	@# Config files are strictly ASCII. Rust source is allowed a small allowlist
	@# of UTF-8 characters that appear in spec-section references in comments
	@# (e.g. "[IEEE 802.11-2024] section 12.7.2"). Historically this list is
	@# just the section sign; extend cautiously.
	@fail=0; \
	for f in $$(git ls-files -- '*.toml' '*.yml' '*.yaml' '*.json' '*.sh' 'Makefile'); do \
		if LC_ALL=C grep -Pn '[^\x00-\x7F]' "$$f" > /dev/null 2>&1; then \
			echo "  NON-ASCII: $$f"; \
			LC_ALL=C grep -Pn '[^\x00-\x7F]' "$$f"; \
			fail=1; \
		fi; \
	done; \
	for f in $$(git ls-files -- '*.rs'); do \
		if LC_ALL=C grep -Pn '[^\x00-\x7F\xC2\xA7]' "$$f" > /dev/null 2>&1; then \
			echo "  NON-ASCII (outside allowlist): $$f"; \
			LC_ALL=C grep -Pn '[^\x00-\x7F\xC2\xA7]' "$$f"; \
			fail=1; \
		fi; \
	done; \
	if [ "$$fail" -eq 1 ]; then echo "FAIL: non-ASCII bytes found"; exit 1; fi
	@echo "OK: tracked files conform to ASCII / allowlisted-UTF-8 policy."

lf-check:
	@echo "Checking for CRLF line endings in tracked files..."
	@fail=0; \
	for f in $$(git ls-files -- '*.rs' '*.toml' '*.yml' '*.yaml' '*.json' '*.sh' 'Makefile'); do \
		if grep -Pq '\r$$' "$$f" 2>/dev/null; then \
			echo "  CRLF: $$f"; \
			fail=1; \
		fi; \
	done; \
	if [ "$$fail" -eq 1 ]; then echo "FAIL: CRLF line endings found"; exit 1; fi
	@echo "OK: all source files use LF."

hygiene: ascii-check lf-check

# -- Platform-specific build targets -------------------------------------------
#
# Targets install their required rustup target if missing (idempotent, no-op
# if already present). The caller is responsible for system-level deps:
#
#   Linux musl: apt install musl-tools
#   macOS:      no extra deps (lipo is part of Xcode Command Line Tools)
#   Windows:    CI-only -- native runners have MSVC + MinGW available
#
# wpawolf has no platform-conditional dependencies (pure-Rust + flate2's
# rust_backend), so every target builds with the same flags.

# -- Linux x86_64 --------------------------------------------------------------
#
# Static binary -- no glibc dep. Runs on any Linux distro with a recent kernel.
build-linux-musl:
	@if ! command -v musl-gcc > /dev/null 2>&1; then \
		echo "WARNING: musl-gcc not found -- skipping $(TARGET_LINUX_X86_MUSL)."; \
		echo "  Install: apt install musl-tools && rustup target add $(TARGET_LINUX_X86_MUSL)"; \
	else \
		rustup target add $(TARGET_LINUX_X86_MUSL) 2>/dev/null || true; \
		$(CARGO) build --profile release -p wpawolf --bin wpawolf --target $(TARGET_LINUX_X86_MUSL); \
	fi

# -- Linux arm64 ---------------------------------------------------------------
#
# Run on an ARM64 Linux machine (or the ubuntu-24.04-arm CI runner).
build-linux-arm-musl:
	@if ! command -v musl-gcc > /dev/null 2>&1; then \
		echo "WARNING: musl-gcc not found -- skipping $(TARGET_LINUX_ARM_MUSL)."; \
		echo "  Install: apt install musl-tools && rustup target add $(TARGET_LINUX_ARM_MUSL)"; \
	else \
		rustup target add $(TARGET_LINUX_ARM_MUSL) 2>/dev/null || true; \
		$(CARGO) build --profile release -p wpawolf --bin wpawolf --target $(TARGET_LINUX_ARM_MUSL); \
	fi

# -- macOS ---------------------------------------------------------------------
#
# Cross-compilation between arm64 and x86_64 is trivial within macOS -- both
# targets can be built from either Apple Silicon or Intel without extra tools.

# Apple Silicon (M-series) binary.
build-macos-arm:
	rustup target add $(TARGET_MACOS_ARM) 2>/dev/null || true
	$(CARGO) build --profile release -p wpawolf --bin wpawolf --target $(TARGET_MACOS_ARM)

# Intel binary (cross-compiles from Apple Silicon or builds natively on Intel).
build-macos-x86:
	rustup target add $(TARGET_MACOS_X86) 2>/dev/null || true
	$(CARGO) build --profile release -p wpawolf --bin wpawolf --target $(TARGET_MACOS_X86)

# Universal binary: merge arm64 + x86_64 slices with lipo.
# Prerequisite: both build-macos-arm and build-macos-x86 must have run first.
build-macos-universal:
	@if ! command -v lipo > /dev/null 2>&1; then \
		echo "WARNING: lipo not found -- skipping universal binary (macOS only)."; \
	elif [ ! -f target/$(TARGET_MACOS_ARM)/release/$(BIN) ] \
	  || [ ! -f target/$(TARGET_MACOS_X86)/release/$(BIN) ]; then \
		echo "WARNING: one or both macOS binaries missing -- run build-macos-arm and build-macos-x86 first."; \
	else \
		mkdir -p $(DIST); \
		lipo -create \
			-output $(DIST)/$(BIN)-macos-universal \
			target/$(TARGET_MACOS_ARM)/release/$(BIN) \
			target/$(TARGET_MACOS_X86)/release/$(BIN); \
		lipo -info $(DIST)/$(BIN)-macos-universal; \
	fi

# -- Windows -------------------------------------------------------------------
#
# All Windows variants are built on native GitHub Actions runners.
# MSVC builds run on windows-latest / windows-11-arm.
# GNU (MinGW) build runs on ubuntu-latest -- simpler than cross from Windows.
build-windows:
	@echo "Windows builds require native CI runners:"
	@echo "  windows-x86_64-msvc.exe  --  windows-latest    (MSVC)"
	@echo "  windows-x86_64-gnu.exe   --  ubuntu-latest     (MinGW, apt install gcc-mingw-w64-x86-64)"
	@echo "  windows-arm64-msvc.exe   --  windows-11-arm    (MSVC)"
	@echo "Trigger: git tag vX.Y.Z && git push --tags"

# -- Distribution --------------------------------------------------------------
#
# 'make dist' (and 'make all') detects the current OS and architecture, builds
# the appropriate release artifacts, and collects them into dist/.
#
#   Linux  x86_64 -> linux-x86_64 (musl static)
#   Linux  arm64  -> linux-arm64  (musl static)
#   macOS  any    -> macos-arm64 + macos-x86_64 + macos-universal (lipo)
#   Windows       -> CI-only (run git tag to trigger release workflow)
#
# Full multi-platform release: git tag vX.Y.Z && git push --tags
#   -> triggers .github/workflows/release.yml on native runners for all targets

ifeq ($(PLATFORM)-$(ARCH),linux-x86_64)
dist: build-linux-musl
	@mkdir -p $(DIST)
	@built=0; \
	if [ -f target/$(TARGET_LINUX_X86_MUSL)/release/$(BIN) ]; then \
		cp target/$(TARGET_LINUX_X86_MUSL)/release/$(BIN) $(DIST)/$(BIN)-linux-x86_64; \
		echo "  $(DIST)/$(BIN)-linux-x86_64  (musl static)"; \
		built=$$((built+1)); \
	fi; \
	echo "$$built artifact(s) in $(DIST)/  |  ARM64/Windows/macOS: git tag vX.Y.Z && git push --tags"

else ifeq ($(PLATFORM)-$(ARCH),linux-arm64)
dist: build-linux-arm-musl
	@mkdir -p $(DIST)
	@built=0; \
	if [ -f target/$(TARGET_LINUX_ARM_MUSL)/release/$(BIN) ]; then \
		cp target/$(TARGET_LINUX_ARM_MUSL)/release/$(BIN) $(DIST)/$(BIN)-linux-arm64; \
		echo "  $(DIST)/$(BIN)-linux-arm64  (musl static)"; \
		built=$$((built+1)); \
	fi; \
	echo "$$built artifact(s) in $(DIST)/  |  x86_64/Windows/macOS: git tag vX.Y.Z && git push --tags"

else ifeq ($(PLATFORM),macos)
dist: build-macos-arm build-macos-x86 build-macos-universal
	@mkdir -p $(DIST)
	@built=0; \
	if [ -f target/$(TARGET_MACOS_ARM)/release/$(BIN) ]; then \
		cp target/$(TARGET_MACOS_ARM)/release/$(BIN) $(DIST)/$(BIN)-macos-arm64; \
		echo "  $(DIST)/$(BIN)-macos-arm64"; \
		built=$$((built+1)); \
	fi; \
	if [ -f target/$(TARGET_MACOS_X86)/release/$(BIN) ]; then \
		cp target/$(TARGET_MACOS_X86)/release/$(BIN) $(DIST)/$(BIN)-macos-x86_64; \
		echo "  $(DIST)/$(BIN)-macos-x86_64"; \
		built=$$((built+1)); \
	fi; \
	if [ -f $(DIST)/$(BIN)-macos-universal ]; then \
		echo "  $(DIST)/$(BIN)-macos-universal  (lipo)"; \
		built=$$((built+1)); \
	fi; \
	echo "$$built artifact(s) in $(DIST)/  |  Linux/Windows: git tag vX.Y.Z && git push --tags"

else
# Windows -- native runners required for MSVC; GNU cross-compiled from Ubuntu in CI.
dist: build-windows
endif

# -- Size reporting -------------------------------------------------------------

# Show sizes for all artifacts present in dist/ (local + any from CI).
size: build
	@echo "Binary sizes:"
	@ls -lh $(DIST)/$(BIN)-linux-x86_64 2>/dev/null \
		| awk '{print "  linux-x86_64 (musl):     " $$5}' || true
	@ls -lh $(DIST)/$(BIN)-linux-arm64 2>/dev/null \
		| awk '{print "  linux-arm64  (musl):     " $$5}' || true
	@ls -lh $(DIST)/$(BIN)-macos-arm64 2>/dev/null \
		| awk '{print "  macos-arm64:             " $$5}' || true
	@ls -lh $(DIST)/$(BIN)-macos-x86_64 2>/dev/null \
		| awk '{print "  macos-x86_64:            " $$5}' || true
	@ls -lh $(DIST)/$(BIN)-macos-universal 2>/dev/null \
		| awk '{print "  macos-universal (lipo):  " $$5}' || true
	@ls -lh $(DIST)/$(BIN)-windows-x86_64-msvc.exe 2>/dev/null \
		| awk '{print "  windows-x86_64-msvc:     " $$5}' || true
	@ls -lh $(DIST)/$(BIN)-windows-x86_64-gnu.exe 2>/dev/null \
		| awk '{print "  windows-x86_64-gnu:      " $$5}' || true
	@ls -lh $(DIST)/$(BIN)-windows-arm64-msvc.exe 2>/dev/null \
		| awk '{print "  windows-arm64-msvc:      " $$5}' || true

# -- Convenience ---------------------------------------------------------------

fix: fmt-fix lint-fix

hooks:
	git config core.hooksPath .githooks
	@echo "Git hooks installed (.githooks/pre-commit)"

clean:
	$(CARGO) clean
	rm -rf $(DIST)
	# Note: ~/.cargo/advisory-db is intentionally preserved so `make audit`
	# remains usable after a clean. Remove it manually if you need a fresh
	# advisory fetch.

# -- Gates ---------------------------------------------------------------------

# Full verification gate -- run before every push.
check-all: fmt lint audit audit-citations check test-matrix doc hygiene machete
