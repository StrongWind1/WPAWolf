//! Disk-backed deduplication via partitioned fingerprint bucket files.
//!
//! When in-memory dedup (`PerSinkDedup`) would exceed the memory threshold,
//! this module takes over. Hash lines are written directly to output files
//! (write-through, accepting temporary duplicates). Each line's u64 `SipHash`
//! fingerprint plus its line number are appended to one of 256 bucket files
//! per sink (`fingerprint % 256`). After emission completes, a cleaning pass
//! loads buckets one at a time, identifies duplicate fingerprints, and rewrites
//! each output file without the duplicates.
//!
//! # Bucket file format
//!
//! Each bucket stores a sequence of 16-byte records (u64 LE pairs):
//! ```text
//! offset  len  field
//! 0       8    line_number (u64 LE) -- 0-based index within the sink's output
//! 8       8    fingerprint (u64 LE) -- SipHash-1-3 of the hash line fields
//! ```
//!
//! Records with `line_number == u64::MAX` are sentinels from mid-emission
//! switchover: they represent fingerprints that were already deduped in memory
//! and count as "first occurrence" during the cleaning pass.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use crate::output::dedup::SinkId;
use crate::types::Result;

const NUM_BUCKETS: usize = 256;
const RECORD_SIZE: usize = 16;
const SENTINEL_LINE: u64 = u64::MAX;
const BUCKET_BUF_CAPACITY: usize = 32 * 1024;
const CLEAN_BUF_CAPACITY: usize = 64 * 1024;

// --- DiskDedupSink ---

/// Per-sink bucket file state.
struct DiskDedupSink {
    bucket_writers: Vec<Option<BufWriter<std::fs::File>>>,
    bucket_dir: PathBuf,
    line_count: u64,
}

impl DiskDedupSink {
    fn new(bucket_dir: PathBuf, line_base: u64) -> Result<Self> {
        std::fs::create_dir_all(&bucket_dir)
            .map_err(|e| crate::types::Error::io(e, bucket_dir.clone(), "create dedup bucket dir"))?;
        Ok(Self { bucket_writers: (0..NUM_BUCKETS).map(|_| None).collect(), bucket_dir, line_count: line_base })
    }

    #[expect(clippy::indexing_slicing, reason = "bucket_idx always < NUM_BUCKETS from % operation")]
    fn get_or_create_writer(&mut self, bucket_idx: usize) -> Result<&mut BufWriter<std::fs::File>> {
        if self.bucket_writers[bucket_idx].is_none() {
            let path = self.bucket_dir.join(format!("b{bucket_idx:03}.bin"));
            let file = std::fs::File::create(&path)
                .map_err(|e| crate::types::Error::io(e, path, "create dedup bucket file"))?;
            self.bucket_writers[bucket_idx] = Some(BufWriter::with_capacity(BUCKET_BUF_CAPACITY, file));
        }
        Ok(self.bucket_writers[bucket_idx].as_mut().unwrap_or_else(|| unreachable!()))
    }

    fn record(&mut self, fingerprint: u64) -> Result<()> {
        #[expect(clippy::cast_possible_truncation, reason = "fingerprint % 256 always fits usize")]
        let bucket_idx = (fingerprint % NUM_BUCKETS as u64) as usize;
        let line_number = self.line_count;
        self.line_count += 1;
        let writer = self.get_or_create_writer(bucket_idx)?;
        writer.write_all(&line_number.to_le_bytes())?;
        writer.write_all(&fingerprint.to_le_bytes())?;
        Ok(())
    }

    fn record_sentinel(&mut self, fingerprint: u64) -> Result<()> {
        #[expect(clippy::cast_possible_truncation, reason = "fingerprint % 256 always fits usize")]
        let bucket_idx = (fingerprint % NUM_BUCKETS as u64) as usize;
        let writer = self.get_or_create_writer(bucket_idx)?;
        writer.write_all(&SENTINEL_LINE.to_le_bytes())?;
        writer.write_all(&fingerprint.to_le_bytes())?;
        Ok(())
    }

    fn flush_all(&mut self) -> Result<()> {
        for w in self.bucket_writers.iter_mut().flatten() {
            w.flush()?;
        }
        Ok(())
    }
}

// --- DiskDedup ---

/// Monotonic counter for unique temp directory names when multiple `DiskDedup`
/// instances are created in the same process (e.g. a mid-stream switch, tests).
static INSTANCE_COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);

/// Disk-backed deduplication coordinator for all output sinks.
pub struct DiskDedup {
    sinks: [Option<DiskDedupSink>; SinkId::COUNT],
    base_dir: PathBuf,
}

impl DiskDedup {
    /// Creates a new `DiskDedup` with bucket directories for each active sink.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the temp directory cannot be created.
    pub fn new(active_mask: &[bool; SinkId::COUNT]) -> Result<Self> {
        Self::new_with_offsets(active_mask, &[0; SinkId::COUNT])
    }

    /// Like [`Self::new`] but seeds each sink's line counter from `line_offsets`.
    ///
    /// Used for a mid-emission switchover: lines were already written to the
    /// output files in memory-dedup mode, so `record()` must number new lines from
    /// that base. `rewrite_without_lines` indexes *absolute* file lines, so a base
    /// of 0 here would make the cleaning pass remove the wrong lines.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the temp directory cannot be created.
    pub fn new_with_offsets(
        active_mask: &[bool; SinkId::COUNT],
        line_offsets: &[usize; SinkId::COUNT],
    ) -> Result<Self> {
        let seq = INSTANCE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let base_dir = std::env::temp_dir().join(format!("wpawolf_dedup_{}_{seq}", std::process::id()));
        std::fs::create_dir_all(&base_dir)
            .map_err(|e| crate::types::Error::io(e, base_dir.clone(), "create dedup temp dir"))?;

        let mut sinks: [Option<DiskDedupSink>; SinkId::COUNT] = Default::default();
        for (idx, active) in active_mask.iter().enumerate() {
            if *active {
                let sink_dir = base_dir.join(format!("sink_{idx}"));
                let line_base = line_offsets.get(idx).copied().map_or(0, |n| u64::try_from(n).unwrap_or(u64::MAX));
                if let Some(slot) = sinks.get_mut(idx) {
                    *slot = Some(DiskDedupSink::new(sink_dir, line_base)?);
                }
            }
        }

        Ok(Self { sinks, base_dir })
    }

    /// Records a fingerprint for a line just written to `sink`.
    ///
    /// # Errors
    ///
    /// Returns `Err` on I/O failure.
    pub fn record(&mut self, sink: SinkId, fingerprint: u64) -> Result<()> {
        if let Some(Some(ds)) = self.sinks.get_mut(sink.as_index()) {
            ds.record(fingerprint)?;
        }
        Ok(())
    }

    /// Flushes an in-memory `HashSet<u64>` to bucket files with sentinel line numbers.
    ///
    /// # Errors
    ///
    /// Returns `Err` on I/O failure.
    pub fn flush_hashset(&mut self, sink: SinkId, set: &HashSet<u64>) -> Result<()> {
        if let Some(Some(ds)) = self.sinks.get_mut(sink.as_index()) {
            for &fp in set {
                ds.record_sentinel(fp)?;
            }
        }
        Ok(())
    }

    /// Runs the post-emission cleaning pass for all active sinks.
    ///
    /// For each sink that has bucket data:
    /// 1. Flush bucket writers.
    /// 2. Load buckets one at a time, sort by fingerprint, identify duplicates.
    /// 3. Collect line numbers to remove (all but first occurrence of each
    ///    duplicate fingerprint, excluding sentinels).
    /// 4. Rewrite the output file without the removal lines.
    ///
    /// # Errors
    ///
    /// Returns `Err` on I/O failure.
    pub fn clean_all<F>(&mut self, sink_path: F) -> Result<()>
    where
        F: Fn(SinkId) -> Option<PathBuf>,
    {
        for (idx, slot) in self.sinks.iter_mut().enumerate() {
            let Some(ds) = slot.as_mut() else { continue };
            ds.flush_all()?;

            let Some(sink_id) = SinkId::from_index(idx) else { continue };
            let Some(output_path) = sink_path(sink_id) else { continue };

            let removal = build_removal_set(&ds.bucket_dir)?;
            if !removal.is_empty() {
                rewrite_without_lines(&output_path, &removal)?;
            }
        }
        Ok(())
    }

    /// Deletes all bucket files and directories.
    pub fn cleanup(&mut self) {
        for slot in &mut self.sinks {
            if let Some(mut ds) = slot.take() {
                // Drop all writers before removing files.
                for w in &mut ds.bucket_writers {
                    *w = None;
                }
                let _ = std::fs::remove_dir_all(&ds.bucket_dir);
            }
        }
        let _ = std::fs::remove_dir_all(&self.base_dir);
    }
}

impl Drop for DiskDedup {
    fn drop(&mut self) {
        self.cleanup();
    }
}

impl std::fmt::Debug for DiskDedup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let active: usize = self.sinks.iter().filter(|s| s.is_some()).count();
        f.debug_struct("DiskDedup")
            .field("active_sinks", &active)
            .field("base_dir", &self.base_dir)
            .finish_non_exhaustive()
    }
}

// --- Cleaning pass helpers ---

/// Loads all bucket files from `bucket_dir`, identifies duplicate fingerprints,
/// and returns the set of line numbers to remove from the output file.
fn build_removal_set(bucket_dir: &Path) -> Result<HashSet<u64>> {
    let mut removal = HashSet::new();

    for bucket_idx in 0..NUM_BUCKETS {
        let path = bucket_dir.join(format!("b{bucket_idx:03}.bin"));
        let Ok(meta) = std::fs::metadata(&path) else { continue };
        if meta.len() == 0 {
            continue;
        }

        let mut records = load_bucket(&path)?;
        if records.is_empty() {
            continue;
        }

        // Sort by fingerprint, then by line number (sentinels sort last within
        // a fingerprint group, but we handle them explicitly).
        records.sort_unstable_by_key(|&(line, fp)| (fp, line));

        // Walk runs of identical fingerprints.
        let mut i = 0;
        while i < records.len() {
            let fp = records.get(i).map_or(0, |r| r.1);
            let run_start = i;
            while i < records.len() && records.get(i).map_or(0, |r| r.1) == fp {
                i += 1;
            }
            let run_end = i;

            if run_end - run_start <= 1 {
                continue;
            }

            // Find the first non-sentinel in the run. If a sentinel exists,
            // it counts as "first occurrence" (already deduped in memory).
            let has_sentinel = (run_start..run_end).any(|j| records.get(j).map_or(0, |r| r.0) == SENTINEL_LINE);

            if has_sentinel {
                // All non-sentinel entries are duplicates of the in-memory original.
                for j in run_start..run_end {
                    let line = records.get(j).map_or(SENTINEL_LINE, |r| r.0);
                    if line != SENTINEL_LINE {
                        removal.insert(line);
                    }
                }
            } else {
                // No sentinel -- keep the first (lowest line number), remove the rest.
                for j in (run_start + 1)..run_end {
                    let line = records.get(j).map_or(SENTINEL_LINE, |r| r.0);
                    if line != SENTINEL_LINE {
                        removal.insert(line);
                    }
                }
            }
        }
    }

    Ok(removal)
}

/// Reads all (`line_number`, fingerprint) records from a bucket file.
fn load_bucket(path: &Path) -> Result<Vec<(u64, u64)>> {
    let file = std::fs::File::open(path)?;
    let file_len = file.metadata()?.len();
    #[expect(clippy::cast_possible_truncation, reason = "bucket files are small; record count fits usize")]
    let record_count = (file_len / RECORD_SIZE as u64) as usize;
    let mut reader = BufReader::with_capacity(CLEAN_BUF_CAPACITY, file);
    let mut records = Vec::with_capacity(record_count);
    let mut buf = [0u8; RECORD_SIZE];

    loop {
        match reader.read_exact(&mut buf) {
            Ok(()) => {
                let line = u64::from_le_bytes([buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]]);
                let fp = u64::from_le_bytes([buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]]);
                records.push((line, fp));
            },
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e.into()),
        }
    }

    Ok(records)
}

/// Rewrites an output file, skipping lines whose 0-based index is in `removal`.
fn rewrite_without_lines(output_path: &Path, removal: &HashSet<u64>) -> Result<()> {
    let clean_path = output_path.with_extension("wpawolf_clean");
    {
        let input = std::fs::File::open(output_path)?;
        let reader = BufReader::with_capacity(CLEAN_BUF_CAPACITY, input);
        let output = std::fs::File::create(&clean_path)?;
        let mut writer = BufWriter::with_capacity(CLEAN_BUF_CAPACITY, output);

        for (line_num, line_result) in reader.lines().enumerate() {
            let line = line_result?;
            if !removal.contains(&(line_num as u64)) {
                writer.write_all(line.as_bytes())?;
                writer.write_all(b"\n")?;
            }
        }
        writer.flush()?;
    }
    std::fs::rename(&clean_path, output_path)?;
    Ok(())
}

// --- Unit tests ---

#[cfg(test)]
mod tests {

    use super::*;
    use crate::output::dedup::SinkId;

    fn active_mask_single() -> [bool; SinkId::COUNT] {
        let mut m = [false; SinkId::COUNT];
        m[SinkId::Out22000.as_index()] = true;
        m
    }

    #[test]
    fn disk_dedup_creates_and_cleans_up() {
        let mut dd = DiskDedup::new(&active_mask_single()).unwrap();
        assert!(dd.base_dir.exists());
        dd.cleanup();
        assert!(!dd.base_dir.exists());
    }

    #[test]
    fn record_and_clean_no_duplicates() {
        let dir = std::env::temp_dir().join(format!("wpawolf_test_dedup_{}_a", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let out_path = dir.join("test.22000");
        std::fs::create_dir_all(&dir).unwrap();

        // Write 3 unique lines to the output file.
        {
            let mut f = std::fs::File::create(&out_path).unwrap();
            writeln!(f, "line_a").unwrap();
            writeln!(f, "line_b").unwrap();
            writeln!(f, "line_c").unwrap();
        }

        let mut dd = DiskDedup::new(&active_mask_single()).unwrap();
        // Record 3 unique fingerprints.
        dd.record(SinkId::Out22000, 100).unwrap();
        dd.record(SinkId::Out22000, 200).unwrap();
        dd.record(SinkId::Out22000, 300).unwrap();

        dd.clean_all(|sink| if sink == SinkId::Out22000 { Some(out_path.clone()) } else { None }).unwrap();

        let content = std::fs::read_to_string(&out_path).unwrap();
        assert_eq!(content, "line_a\nline_b\nline_c\n");

        dd.cleanup();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn record_and_clean_with_duplicates() {
        let dir = std::env::temp_dir().join(format!("wpawolf_test_dedup_{}_b", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let out_path = dir.join("test.22000");
        std::fs::create_dir_all(&dir).unwrap();

        // Write 5 lines: line 0, 1, 2 are unique; line 3 duplicates line 0; line 4 duplicates line 1.
        {
            let mut f = std::fs::File::create(&out_path).unwrap();
            writeln!(f, "unique_a").unwrap();
            writeln!(f, "unique_b").unwrap();
            writeln!(f, "unique_c").unwrap();
            writeln!(f, "dup_of_a").unwrap();
            writeln!(f, "dup_of_b").unwrap();
        }

        let mut dd = DiskDedup::new(&active_mask_single()).unwrap();
        dd.record(SinkId::Out22000, 100).unwrap(); // line 0
        dd.record(SinkId::Out22000, 200).unwrap(); // line 1
        dd.record(SinkId::Out22000, 300).unwrap(); // line 2
        dd.record(SinkId::Out22000, 100).unwrap(); // line 3 -- dup of 0
        dd.record(SinkId::Out22000, 200).unwrap(); // line 4 -- dup of 1

        dd.clean_all(|sink| if sink == SinkId::Out22000 { Some(out_path.clone()) } else { None }).unwrap();

        let content = std::fs::read_to_string(&out_path).unwrap();
        assert_eq!(content, "unique_a\nunique_b\nunique_c\n");

        dd.cleanup();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sentinel_fingerprints_count_as_first_occurrence() {
        let dir = std::env::temp_dir().join(format!("wpawolf_test_dedup_{}_c", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let out_path = dir.join("test.22000");
        std::fs::create_dir_all(&dir).unwrap();

        // 2 lines in output, but fingerprint 100 was already deduped in memory (sentinel).
        {
            let mut f = std::fs::File::create(&out_path).unwrap();
            writeln!(f, "dup_of_sentinel").unwrap();
            writeln!(f, "unique_line").unwrap();
        }

        let mut dd = DiskDedup::new(&active_mask_single()).unwrap();
        // Flush a sentinel for fingerprint 100 (was in memory).
        let mut sentinel_set = HashSet::new();
        sentinel_set.insert(100u64);
        dd.flush_hashset(SinkId::Out22000, &sentinel_set).unwrap();
        // Record output lines.
        dd.record(SinkId::Out22000, 100).unwrap(); // line 0 -- dup of sentinel
        dd.record(SinkId::Out22000, 200).unwrap(); // line 1 -- unique

        dd.clean_all(|sink| if sink == SinkId::Out22000 { Some(out_path.clone()) } else { None }).unwrap();

        let content = std::fs::read_to_string(&out_path).unwrap();
        assert_eq!(content, "unique_line\n", "sentinel should cause line 0 to be removed");

        dd.cleanup();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn new_with_offsets_seeds_line_base_for_midstream_switch() {
        let dir = std::env::temp_dir().join(format!("wpawolf_test_dedup_{}_d", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let out_path = dir.join("test.22000");
        std::fs::create_dir_all(&dir).unwrap();

        // Two pre-switch lines (written in memory-dedup mode), then three
        // write-through lines after a mid-stream switch. Line 4 duplicates the
        // fingerprint of pre-switch line 0.
        {
            let mut f = std::fs::File::create(&out_path).unwrap();
            writeln!(f, "preswitch_0").unwrap(); // absolute line 0, fp 100
            writeln!(f, "preswitch_1").unwrap(); // absolute line 1, fp 200
            writeln!(f, "post_2").unwrap(); // absolute line 2, fp 300
            writeln!(f, "post_3").unwrap(); // absolute line 3, fp 400
            writeln!(f, "dup_of_pre0").unwrap(); // absolute line 4, fp 100 (dup)
        }

        // Switch mid-stream: two lines already written to this sink -> base 2.
        let mut offsets = [0usize; SinkId::COUNT];
        offsets[SinkId::Out22000.as_index()] = 2;
        let mut dd = DiskDedup::new_with_offsets(&active_mask_single(), &offsets).unwrap();

        // Pre-switch in-memory fingerprints become sentinels.
        let mut sentinels = HashSet::new();
        sentinels.insert(100u64);
        sentinels.insert(200u64);
        dd.flush_hashset(SinkId::Out22000, &sentinels).unwrap();

        // Post-switch write-through records number from the seeded base (2, 3, 4).
        dd.record(SinkId::Out22000, 300).unwrap(); // line 2
        dd.record(SinkId::Out22000, 400).unwrap(); // line 3
        dd.record(SinkId::Out22000, 100).unwrap(); // line 4 -- dup of sentinel 100

        dd.clean_all(|sink| if sink == SinkId::Out22000 { Some(out_path.clone()) } else { None }).unwrap();

        let content = std::fs::read_to_string(&out_path).unwrap();
        // Without line-base seeding the removal set would target line 2 and delete
        // "post_2"; seeded, it correctly removes the absolute dup line 4.
        assert_eq!(content, "preswitch_0\npreswitch_1\npost_2\npost_3\n");

        dd.cleanup();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn drop_cleans_up() {
        let dd = DiskDedup::new(&active_mask_single()).unwrap();
        let base = dd.base_dir.clone();
        assert!(base.exists());
        drop(dd);
        assert!(!base.exists());
    }
}
