//! `wpawolf-fixturegen` CLI entry point.
//!
//! ```text
//! wpawolf-fixturegen all       --out tests/fixtures/generated/
//! wpawolf-fixturegen type 2    --out tests/fixtures/generated/
//! wpawolf-fixturegen pmkid 14  --out tests/fixtures/generated/
//! wpawolf-fixturegen combo n3e2 --out tests/fixtures/generated/
//! wpawolf-fixturegen manifest  --out tests/fixtures/generated/
//! ```

#![forbid(unsafe_code)]

// Acknowledged-but-bin-unused dependencies (the lib target is the consumer).
// Same pattern as `wpawolf::main.rs`.
use aes as _;
use cmac as _;
use flate2 as _;
use hmac as _;
use md5 as _;
use pbkdf2 as _;
use sha1 as _;
use sha2 as _;
use subtle as _;
use wpawolf as _;

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use wpawolf_fixturegen::Result;
use wpawolf_fixturegen::catalog::{self, Container, Fixture};
use wpawolf_fixturegen::pcap_writer::{PcapNgEndian, gzip, write_pcap, write_pcapng, write_pcapng_with_endian};

#[derive(Parser, Debug)]
#[command(
    name = "wpawolf-fixturegen",
    version,
    about = "Generate pcap/pcapng test fixtures for the wpawolf parser",
    long_about = "Emits a deterministic corpus of pcap and pcapng files containing 802.11 \
                  management and EAPOL frames covering every combination of (hash type, \
                  PMKID site S1-S20, N#E# pairing combo, link-layer header, container \
                  variant, edge case) recognised by wpawolf. Each fixture carries valid \
                  PMK / PMKID / MIC values derived from a known PSK so the corpus doubles \
                  as a hashcat smoke test."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Generate the full corpus into `--out`.
    All {
        /// Output directory (created if it does not exist).
        #[arg(long)]
        out: PathBuf,
    },
    /// Generate fixtures for one of the 11 hash types.
    Type {
        /// Hash type number (1-11).
        n: u8,
        #[arg(long)]
        out: PathBuf,
    },
    /// Generate the fixture for one PMKID extraction site (S1-S20).
    Pmkid {
        /// PMKID source number (1-20).
        s: u8,
        #[arg(long)]
        out: PathBuf,
    },
    /// Generate the fixture for one N#E# pairing combo.
    Combo {
        /// Combo identifier: `n1e2`, `n1e4`, `n3e2`, `n2e3`, `n4e3`, `n3e4`.
        id: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Re-emit the ground-truth manifest only (no pcap output).
    Manifest {
        #[arg(long)]
        out: PathBuf,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(&cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("wpawolf-fixturegen: {e}");
            ExitCode::FAILURE
        },
    }
}

fn run(cli: &Cli) -> Result<()> {
    match &cli.command {
        Command::All { out } => emit_all(out),
        Command::Type { n, out } => emit_filter(out, |f| fixture_type_number(f) == Some(*n)),
        Command::Pmkid { s, out } => emit_filter(out, |f| fixture_pmkid_site(f) == Some(*s)),
        Command::Combo { id, out } => {
            let id_lc = id.to_lowercase();
            emit_filter(out, move |f| fixture_combo_id(f).is_some_and(|c| c == id_lc))
        },
        Command::Manifest { out } => emit_manifest(out),
    }
}

fn emit_all(out: &Path) -> Result<()> {
    let fixtures = catalog::all()?;
    write_corpus(out, &fixtures)?;
    eprintln!("wrote {} fixtures to {}", fixtures.len(), out.display());
    Ok(())
}

fn emit_filter<F>(out: &Path, predicate: F) -> Result<()>
where
    F: Fn(&Fixture) -> bool,
{
    let fixtures: Vec<Fixture> = catalog::all()?.into_iter().filter(predicate).collect();
    if fixtures.is_empty() {
        eprintln!("no fixtures matched filter");
        return Ok(());
    }
    write_corpus(out, &fixtures)?;
    eprintln!("wrote {} matching fixtures to {}", fixtures.len(), out.display());
    Ok(())
}

fn emit_manifest(out: &Path) -> Result<()> {
    let fixtures = catalog::all()?;
    fs::create_dir_all(out)?;
    write_manifest(out, &fixtures)?;
    eprintln!("manifest -> {}", out.join("ground_truth/manifest.toml").display());
    Ok(())
}

/// Write each fixture to disk and emit the manifest file.
fn write_corpus(out: &Path, fixtures: &[Fixture]) -> Result<()> {
    fs::create_dir_all(out)?;
    for f in fixtures {
        let target = out.join(&f.path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        write_fixture(&target, f)?;
    }
    write_manifest(out, fixtures)?;
    Ok(())
}

/// Serialise one fixture to its container format and write the bytes.
fn write_fixture(target: &Path, fixture: &Fixture) -> Result<()> {
    let mut buf = Vec::with_capacity(fixture.packets.iter().map(|p| p.data.len() + 32).sum::<usize>() + 128);
    match fixture.container {
        Container::Pcap(magic) => write_pcap(&mut buf, magic, fixture.link_type.dlt(), &fixture.packets)?,
        Container::PcapNg => write_pcapng(&mut buf, link_dlt_u16(fixture.link_type.dlt()), &fixture.packets)?,
        Container::PcapNgBe => write_pcapng_with_endian(
            &mut buf,
            PcapNgEndian::Big,
            link_dlt_u16(fixture.link_type.dlt()),
            &fixture.packets,
        )?,
        Container::PcapGz(magic) => {
            let mut inner = Vec::new();
            write_pcap(&mut inner, magic, fixture.link_type.dlt(), &fixture.packets)?;
            buf = gzip(&inner)?;
        },
        Container::PcapNgGz => {
            let mut inner = Vec::new();
            write_pcapng(&mut inner, link_dlt_u16(fixture.link_type.dlt()), &fixture.packets)?;
            buf = gzip(&inner)?;
        },
    }
    fs::write(target, &buf)?;
    Ok(())
}

/// Truncate a `u32` DLT to the `u16` IDB linktype field, clamping rather
/// than panicking. All real DLTs fit in 16 bits.
fn link_dlt_u16(dlt: u32) -> u16 {
    u16::try_from(dlt).unwrap_or(u16::MAX)
}

/// Emit the ground-truth manifest that the integration test diffs against.
///
/// Hand-rolled TOML keeps `serde` out of the dependency budget; the schema
/// is stable and tiny.
fn write_manifest(out: &Path, fixtures: &[Fixture]) -> Result<()> {
    let dir = out.join("ground_truth");
    fs::create_dir_all(&dir)?;
    let mut text = String::new();
    text.push_str("# wpawolf-fixturegen ground-truth manifest. Generated; do not edit.\n");
    text.push_str("# Each [[fixture]] block documents one corpus file and the hashcat\n");
    text.push_str("# lines wpawolf is expected to emit when run against it.\n\n");
    for f in fixtures {
        text.push_str("[[fixture]]\n");
        // `write!` to a String is infallible (writes to memory only); the
        // unwrap is the canonical idiom and is exempted from the
        // `unwrap_used` lint via the test relaxation. In the binary target
        // we propagate via `?` against a panic-free `core::fmt::Error`.
        writeln!(text, "path = \"{}\"", f.path.display()).map_err(io_other)?;
        writeln!(text, "description = \"{}\"", escape_toml(&f.description)).map_err(io_other)?;
        writeln!(text, "container = \"{}\"", container_name(f.container)).map_err(io_other)?;
        writeln!(text, "link_type = \"{}\"", link_name(f.link_type.dlt())).map_err(io_other)?;
        writeln!(text, "packet_count = {}", f.packets.len()).map_err(io_other)?;
        text.push_str("expected_hashes = [\n");
        for h in &f.expected_hashes {
            writeln!(text, "    \"{}\",", escape_toml(h)).map_err(io_other)?;
        }
        text.push_str("]\n");
        text.push_str("forbidden_hashes = [\n");
        for h in &f.forbidden_hashes {
            writeln!(text, "    \"{}\",", escape_toml(h)).map_err(io_other)?;
        }
        text.push_str("]\n\n");
    }
    fs::write(dir.join("manifest.toml"), text)?;
    Ok(())
}

fn escape_toml(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

const fn container_name(c: Container) -> &'static str {
    match c {
        Container::Pcap(_) => "pcap",
        Container::PcapNg => "pcapng_le",
        Container::PcapNgBe => "pcapng_be",
        Container::PcapGz(_) => "pcap.gz",
        Container::PcapNgGz => "pcapng.gz",
    }
}

const fn link_name(dlt: u32) -> &'static str {
    match dlt {
        105 => "raw_802_11",
        119 => "prism",
        127 => "radiotap",
        163 => "avs",
        192 => "ppi",
        _ => "unknown",
    }
}

/// Convert a `core::fmt::Error` (only raised by `write!` to a `String` if
/// the underlying buffer somehow fails) into a [`std::io::Error`] so the
/// caller can keep returning the crate-local [`Result`].
fn io_other(_: core::fmt::Error) -> std::io::Error {
    std::io::Error::other("formatting error")
}

fn fixture_type_number(f: &Fixture) -> Option<u8> {
    let path = f.path.to_string_lossy();
    let stem = path.strip_prefix("11_types/")?;
    let digits = stem.strip_prefix("type")?.get(..2)?;
    digits.parse::<u8>().ok()
}

fn fixture_pmkid_site(f: &Fixture) -> Option<u8> {
    let path = f.path.to_string_lossy();
    let stem = path.strip_prefix("20_pmkid_sites/")?;
    let digits = stem.strip_prefix('s')?.get(..2)?;
    digits.parse::<u8>().ok()
}

fn fixture_combo_id(f: &Fixture) -> Option<String> {
    let path = f.path.to_string_lossy();
    let stem = path.strip_prefix("6_combos/")?;
    Some(stem.split('.').next()?.to_owned())
}
