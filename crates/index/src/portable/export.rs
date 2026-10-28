//! Export: stream the `TxLookup` family of one coherent snapshot into a
//! hashed artifact, then publish the manifest last.
//!
//! Every exported locator must equal a real top-level block transaction
//! boundary: the recorded offset and length must match one parsed transaction
//! span of the block body, the same rule restore enforces.
//!
//! Consistency: the row stream is read from one point-in-time key-value
//! snapshot whose `TxLookup` watermark is the applied tip (snapshot
//! isolation). The writer's fenced watermark capture before and after the
//! stream is a linearizable compare; any movement aborts and removes the
//! output, so a published manifest always names a bundle taken at one
//! watermark. Re-running an export into a fresh directory is idempotent: it
//! reads state and writes only new files.

use super::artifact::{
    ARTIFACT_VERSION, ArtifactHeader, CANCEL_POLL_RECORDS, HEADER_LEN, IO_BUFFER_BYTES, hash_file,
    positions_are_valid, write_record,
};
use super::chain::{BodyReader, ChainBase, Located};
use super::manifest::{
    BundleFamily, BundleIdentity, IndexBundleManifestV1, IndexMode, MANIFEST_FILE, TxLookupArtifact,
};
use super::{BundleHost, ExportReport, IndexBundleError, IndexBundleRequest, io_error, sync_dir};
use crate::types::{HashPrefixRow, TxPosition, TxPositionValue};
use crate::{
    IndexCapability, IndexError, IndexWatermark, IndexWriteFence, TxIndexFamily, TxIndexScanRow,
};
use bitcoin_rs_chain::BlockBodySource;
use bitcoin_rs_storage::{PrefixScanLimit, StorageError};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Rows per export page. Export streams the family through bounded pages,
/// each read through a short-lived snapshot, so export memory stays flat in
/// family size on every backend instead of materializing the whole family
/// before emitting rows.
const EXPORT_PAGE_ROWS: usize = 1_024;
/// Cap on returned key-plus-value bytes per page after the first row.
const EXPORT_PAGE_BYTES: usize = 1 << 20;

/// Limit for one export page scan.
fn export_page_limit() -> PrefixScanLimit {
    PrefixScanLimit {
        max_rows: EXPORT_PAGE_ROWS,
        max_bytes: EXPORT_PAGE_BYTES,
    }
}

/// Directory fsync used by a [`Publication`].
type SyncDir = fn(&Path) -> Result<(), IndexBundleError>;

/// Owns every file one export creates in its bundle directory.
///
/// Files are created with create-new, so an entry that existed before the
/// export is never opened, replaced, or removed. Until [`Self::commit`]
/// makes the final directory entry durable, dropping the publication removes
/// the created files newest first: the manifest goes before the artifact it
/// names, and the artifact is removed only once the manifest's removal is
/// itself durable. A failed, stale, or cancelled export therefore never
/// leaves a manifest that names a missing artifact.
struct Publication {
    dir: PathBuf,
    /// Created paths, oldest first.
    created: Vec<PathBuf>,
    committed: bool,
    sync: SyncDir,
}

impl Publication {
    fn new(dir: &Path) -> Self {
        Self::with_sync(dir, sync_dir)
    }

    fn with_sync(dir: &Path, sync: SyncDir) -> Self {
        Self {
            dir: dir.to_path_buf(),
            created: Vec::new(),
            committed: false,
            sync,
        }
    }

    /// Creates `path`, refusing to overwrite anything already there, and
    /// takes ownership of its removal.
    fn create_new(&mut self, path: &Path) -> Result<File, IndexBundleError> {
        let file = create_new_file(path)?;
        self.created.push(path.to_path_buf());
        Ok(file)
    }

    /// Makes every created entry durable. Only success disarms the cleanup;
    /// a failed directory fsync is returned, never retried, and the drop
    /// removes the created files.
    fn commit(mut self) -> Result<(), IndexBundleError> {
        (self.sync)(&self.dir)?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for Publication {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        while let Some(path) = self.created.pop() {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    tracing::warn!(
                        path = %path.display(),
                        %error,
                        "cannot remove a file of an unpublished index bundle; leaving older files in place"
                    );
                    return;
                }
            }
            if let Err(error) = (self.sync)(&self.dir) {
                // The removal may not be durable; removing an older file now
                // could leave a surviving manifest naming a missing artifact.
                tracing::warn!(
                    path = %path.display(),
                    %error,
                    "cannot make an unpublished index bundle removal durable; leaving older files in place"
                );
                return;
            }
        }
    }
}

/// Creates `path`, refusing to overwrite anything already there.
fn create_new_file(path: &Path) -> Result<File, IndexBundleError> {
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| {
            if error.kind() == io::ErrorKind::AlreadyExists {
                IndexBundleError::ExistingBundle(path.to_path_buf())
            } else {
                io_error(path, error)
            }
        })
}

/// Exports the `TxLookup` family at the applied tip into `request.dir`.
pub(super) fn export(
    host: &BundleHost<'_>,
    request: &IndexBundleRequest,
) -> Result<ExportReport, IndexBundleError> {
    if !host.enabled.contains(IndexCapability::TxLookup) {
        return Err(IndexBundleError::TxLookupDisabled);
    }
    let dir = request.dir.as_path();
    let manifest_path = dir.join(MANIFEST_FILE);
    if manifest_path
        .try_exists()
        .map_err(|error| io_error(&manifest_path, error))?
    {
        return Err(IndexBundleError::ExistingBundle(manifest_path));
    }

    let captured = Captured::take(host)?;
    fs::create_dir_all(dir).map_err(|error| io_error(dir, error))?;
    let artifact_path = dir.join(BundleFamily::TxLookup.file_name());
    let mut publication = Publication::new(dir);
    let file = publication.create_new(&artifact_path)?;
    let identity = captured.identity(request);
    let artifact = captured.write_artifact(host, file, &artifact_path, &identity)?;

    // Abort stale output: the writer must still show exactly the captured
    // fence (reset state, ordinary revision, and watermarks), or the stream
    // may describe rows the index no longer holds; an equal watermark alone
    // would miss a completed reset and rebuild in between.
    let (after, _) = host.writer.fenced_watermarks()?;
    if after != captured.fence {
        return Err(IndexBundleError::Stale);
    }

    // The artifact's directory entry is durable before any manifest names it.
    sync_dir(dir)?;
    let mode = if host.enabled.contains(IndexCapability::ScriptHistory) {
        IndexMode::Full
    } else {
        IndexMode::Utxo
    };
    let manifest = IndexBundleManifestV1::for_tx_lookup(&identity, mode, captured.floor, &artifact);
    write_manifest(&mut publication, &manifest_path, &manifest.to_json()?)?;
    publication.commit()?;
    Ok(ExportReport {
        base: IndexWatermark {
            height: captured.chain.height,
            hash: captured.chain.hash,
        },
        records: artifact.records,
        bytes: artifact.bytes,
    })
}

/// Writes and fsyncs `manifest.json` with create-new. Its directory entry
/// becomes durable only through [`Publication::commit`]; until then the
/// publication removes it on failure.
fn write_manifest(
    publication: &mut Publication,
    path: &Path,
    json: &[u8],
) -> Result<(), IndexBundleError> {
    let mut file = publication.create_new(path)?;
    file.write_all(json)
        .and_then(|()| file.sync_all())
        .map_err(|error| io_error(path, error))
}

/// Everything an export fixes at its start: the exact watermarks, the chain
/// identity of the applied tip, and the base watermark every per-page
/// snapshot must still show.
struct Captured<'a> {
    fence: IndexWriteFence,
    chain: ChainBase,
    /// The applied tip's cumulative transaction count, which is the base's.
    chain_tx_count: u64,
    base: IndexWatermark,
    floor: u32,
    bodies: &'a dyn BlockBodySource,
}

impl<'a> Captured<'a> {
    /// Requires the `TxLookup` watermark to be exactly the applied tip and the
    /// snapshot to agree with it; otherwise nothing is written.
    fn take(host: &BundleHost<'a>) -> Result<Self, IndexBundleError> {
        let (fence, watermarks) = host.writer.fenced_watermarks()?;
        let base = watermarks
            .tx_lookup
            .ok_or(IndexBundleError::NotReady("txindex has no watermark"))?;
        let tip = host
            .applied_tip
            .load_full()
            .ok_or(IndexBundleError::NotReady("there is no applied tip"))?;
        if base.height != tip.height || base.hash != tip.hash.to_le_bytes() {
            return Err(IndexBundleError::NotReady(
                "the txindex watermark is not at the applied tip",
            ));
        }
        let chain = ChainBase::capture(host.block_tree, &tip, tip.height, host.cancelled)?;
        if !chain.validated {
            return Err(IndexBundleError::NotReady(
                "the base block is not on the active chain",
            ));
        }
        // The base is the applied tip, so no block lies above it to read.
        let chain_tx_count = chain.counted_base().ok_or(IndexBundleError::NotReady(
            "the chain transaction count at the base is not established",
        ))?;
        let bodies = host
            .body_source
            .ok_or(IndexBundleError::NotReady("there is no block body source"))?;
        let floor = {
            let snapshot = host.reader.snapshot()?;
            if snapshot.capability_watermark(IndexCapability::TxLookup)? != Some(base) {
                return Err(IndexBundleError::Stale);
            }
            snapshot.capability_floor(IndexCapability::TxLookup)?
        };
        Ok(Self {
            fence,
            chain,
            chain_tx_count,
            base,
            floor,
            bodies,
        })
    }

    fn identity(&self, request: &IndexBundleRequest) -> BundleIdentity {
        BundleIdentity {
            network: request.network,
            genesis: self.chain.genesis,
            format_version: crate::index::index_format_version(),
            base_height: self.chain.height,
            base_hash: self.chain.hash,
            chainwork: self.chain.chainwork,
            chain_tx_count: self.chain_tx_count,
        }
    }

    /// Streams the records, patches the final header over the placeholder,
    /// fsyncs, and returns the artifact's exact identity.
    ///
    /// The header's record and payload counts are known only after the row
    /// stream, and the digest covers the header first, so the digest is taken
    /// by one bounded hashed read of the final fsynced bytes rather than
    /// during the write: it names exactly the file a manifest will publish.
    fn write_artifact(
        &self,
        host: &BundleHost<'_>,
        file: File,
        path: &Path,
        identity: &BundleIdentity,
    ) -> Result<TxLookupArtifact, IndexBundleError> {
        let write = |error| io_error(path, error);
        let mut out = BufWriter::with_capacity(IO_BUFFER_BYTES, file);
        out.write_all(&[0_u8; HEADER_LEN]).map_err(write)?;
        let mut rows = RowExporter {
            host,
            chain: &self.chain,
            floor: self.floor,
            reader: BodyReader::new(self.bodies),
            located: Vec::new(),
            positions: Vec::new(),
            path,
        };
        let (records, payload_bytes) = rows.stream(self.base, &mut out)?;
        let mut file = out
            .into_inner()
            .map_err(|error| io_error(path, error.into_error()))?;
        let header = ArtifactHeader {
            family: BundleFamily::TxLookup,
            artifact_version: ARTIFACT_VERSION,
            index_format: identity.format_version,
            network_magic: identity.network.magic(),
            base_height: identity.base_height,
            base_hash: identity.base_hash,
            records,
            payload_bytes,
        };
        file.seek(SeekFrom::Start(0)).map_err(write)?;
        file.write_all(&header.encode()).map_err(write)?;
        file.sync_all().map_err(write)?;
        drop(file);
        let (sha256, bytes) = hash_file(path).map_err(write)?;
        Ok(TxLookupArtifact {
            sha256,
            bytes,
            records,
            floor: self.floor,
        })
    }
}

/// Turns stored `TxConfirmed` rows into full-txid records, one row at a time.
struct RowExporter<'a> {
    host: &'a BundleHost<'a>,
    chain: &'a ChainBase,
    floor: u32,
    reader: BodyReader<'a>,
    /// `(txid, position)` pairs of the current row, sorted by id then position.
    located: Vec<([u8; 32], TxPosition)>,
    /// Scratch position list of the record being written.
    positions: Vec<TxPosition>,
    path: &'a Path,
}

/// One page row resolved against its block, held for stored-order emission.
struct StagedRow {
    height: u32,
    /// `(txid, position)` pairs sorted by id then position.
    located: Vec<([u8; 32], TxPosition)>,
}

impl RowExporter<'_> {
    /// Streams every row once, in stored-key order, and returns
    /// `(records, payload bytes)`.
    ///
    /// Each page is read through a short-lived snapshot that must still show
    /// `base` at `self.floor`; the snapshot is dropped before any body I/O,
    /// so a long export never pins one key-value snapshot across the whole
    /// family. Rows stream through bounded pages, so no family-sized copy is
    /// made on any backend. Cancellation is polled every
    /// [`CANCEL_POLL_RECORDS`] resolved rows.
    fn stream(
        &mut self,
        base: IndexWatermark,
        out: &mut impl Write,
    ) -> Result<(u64, u64), IndexBundleError> {
        // `host` is itself a shared reference, so copying the cancellation
        // probe out ends the borrow of `self` immediately.
        let cancelled = self.host.cancelled;
        let limit = export_page_limit();
        let mut start_after: Option<Vec<u8>> = None;
        let mut visited = 0_u64;
        let mut totals = (0_u64, 0_u64);
        loop {
            let page = {
                let snapshot = self.host.reader.snapshot()?;
                if snapshot.capability_watermark(IndexCapability::TxLookup)? != Some(base) {
                    return Err(IndexBundleError::Stale);
                }
                if snapshot.capability_floor(IndexCapability::TxLookup)? != self.floor {
                    return Err(IndexBundleError::Stale);
                }
                snapshot.scan_family_page(
                    TxIndexFamily::TxConfirmed,
                    start_after.as_deref(),
                    limit,
                )?
            };
            let (records, bytes) = self.export_page(&page.rows, out, &mut visited, cancelled)?;
            totals.0 += records;
            totals.1 += bytes;
            if page.complete {
                return Ok(totals);
            }
            let Some(last) = page.rows.last() else {
                // A conforming page scan always returns its first row while
                // rows remain; without one there is no cursor to advance.
                return Err(IndexError::from(StorageError::InvalidOperation(
                    "export page scan returned an empty incomplete page",
                ))
                .into());
            };
            // Stored keys are fixed-width: the suffixed key is the least key
            // strictly above the page, so the next page resumes without
            // overlap or gap.
            let mut next = last.row.to_db_row().to_vec();
            next.push(0);
            start_after = Some(next);
        }
    }

    /// Resolves one page grouped by block, then emits records in the page's
    /// stored order.
    ///
    /// Export visits rows in transaction-id order while bodies are keyed by
    /// block, so resolving in stored order reloads and reparses one body per
    /// row. Resolving each bounded page in height order instead keeps
    /// same-block rows adjacent in the body's bounded LRU window;
    /// emission still follows stored order, so the artifact keeps its
    /// strictly ascending record order.
    fn export_page(
        &mut self,
        rows: &[TxIndexScanRow],
        out: &mut impl Write,
        visited: &mut u64,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<(u64, u64), IndexBundleError> {
        let mut order: Vec<usize> = (0..rows.len()).collect();
        order.sort_by_key(|&index| rows[index].row.height());
        let mut staged: Vec<(usize, StagedRow)> = Vec::with_capacity(rows.len());
        for index in order {
            *visited += 1;
            if visited.is_multiple_of(CANCEL_POLL_RECORDS) && cancelled() {
                return Err(IndexBundleError::Cancelled);
            }
            let scan_row = &rows[index];
            self.locate(scan_row.row, &scan_row.value)?;
            staged.push((
                index,
                StagedRow {
                    height: scan_row.row.height(),
                    located: std::mem::take(&mut self.located),
                },
            ));
        }
        staged.sort_by_key(|(index, _)| *index);
        let (mut records, mut bytes) = (0_u64, 0_u64);
        for (_, staged) in &staged {
            let (row_records, row_bytes) = self.emit_row(staged.height, &staged.located, out)?;
            records += row_records;
            bytes += row_bytes;
        }
        Ok((records, bytes))
    }

    /// Writes one record per distinct transaction id in `located`, which must
    /// already be sorted by id then position.
    fn emit_row(
        &mut self,
        height: u32,
        located: &[([u8; 32], TxPosition)],
        out: &mut impl Write,
    ) -> Result<(u64, u64), IndexBundleError> {
        let (mut records, mut bytes) = (0_u64, 0_u64);
        let mut index = 0;
        while index < located.len() {
            let txid = located[index].0;
            let run = located[index..]
                .iter()
                .take_while(|(candidate, _)| *candidate == txid)
                .count();
            self.positions.clear();
            self.positions
                .extend(located[index..index + run].iter().map(|(_, position)| *position));
            bytes += write_record(out, &txid, height, &self.positions)
                .map_err(|error| io_error(self.path, error))?;
            records += 1;
            index += run;
        }
        Ok((records, bytes))
    }

    /// Resolves every position of `row` to its full transaction id, refusing
    /// any position that is not a top-level transaction span whose id carries
    /// the row's prefix. Bytes that merely decode to a transaction elsewhere
    /// in the block never resolve a locator.
    fn locate(&mut self, row: HashPrefixRow, value: &[u8]) -> Result<(), IndexBundleError> {
        let height = row.height();
        let corrupt = |reason: &'static str| IndexBundleError::SourceRow { height, reason };
        if height < self.floor || height > self.chain.height {
            return Err(corrupt("row lies outside the covered heights"));
        }
        let positions = TxPositionValue::decode(value)
            .filter(|positions| positions_are_valid(positions))
            .ok_or_else(|| corrupt("row carries no valid position list"))?;
        let hash = self
            .chain
            .hash_at(self.host.block_tree, height)
            .ok_or_else(|| corrupt("no active-chain block at the row height"))?;
        self.located.clear();
        for &position in positions {
            let tx = match self.reader.transaction(height, hash, position)? {
                Located::Found(tx) => tx,
                Located::BodyMissing => return Err(IndexBundleError::BodyUnavailable { height }),
                Located::Mismatch => {
                    return Err(corrupt("position is not a top-level transaction span"));
                }
            };
            let txid = tx.txid().0.to_le_bytes();
            if txid[..8] != row.prefix {
                return Err(corrupt("transaction id does not match the row prefix"));
            }
            self.located.push((txid, position));
        }
        self.located.sort_unstable_by(|left, right| {
            left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1))
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::error::Error;

    type TestResult = Result<(), Box<dyn Error>>;

    thread_local! {
        static SYNC_CALLS: Cell<u32> = const { Cell::new(0) };
    }

    fn calls() -> u32 {
        SYNC_CALLS.with(Cell::get)
    }

    fn injected(dir: &Path) -> IndexBundleError {
        io_error(dir, io::Error::other("injected directory fsync failure"))
    }

    /// Fails only the first directory fsync: the publication's final commit.
    fn fail_first_sync(dir: &Path) -> Result<(), IndexBundleError> {
        let call = calls();
        SYNC_CALLS.with(|count| count.set(call + 1));
        if call == 0 {
            Err(injected(dir))
        } else {
            sync_dir(dir)
        }
    }

    fn fail_every_sync(dir: &Path) -> Result<(), IndexBundleError> {
        SYNC_CALLS.with(|count| count.set(count.get() + 1));
        Err(injected(dir))
    }

    /// Creates the artifact and manifest the way `export` does.
    fn stage(
        publication: &mut Publication,
        dir: &Path,
    ) -> Result<(PathBuf, PathBuf), Box<dyn Error>> {
        let artifact = dir.join(BundleFamily::TxLookup.file_name());
        let mut file = publication.create_new(&artifact)?;
        file.write_all(b"artifact")?;
        file.sync_all()?;
        drop(file);
        let manifest = dir.join(MANIFEST_FILE);
        write_manifest(publication, &manifest, b"{}")?;
        Ok((artifact, manifest))
    }

    #[test]
    fn failed_final_directory_sync_removes_the_manifest_and_its_artifact() -> TestResult {
        let dir = tempfile::tempdir()?;
        let operator = dir.path().join("operator.dat");
        fs::write(&operator, b"keep")?;
        SYNC_CALLS.with(|count| count.set(0));
        let mut publication = Publication::with_sync(dir.path(), fail_first_sync);
        let (artifact, manifest) = stage(&mut publication, dir.path())?;
        assert!(matches!(
            publication.commit(),
            Err(IndexBundleError::Io { .. })
        ));
        assert!(
            !manifest.exists(),
            "a manifest must not survive a failed commit"
        );
        assert!(
            !artifact.exists(),
            "the artifact is removed after the manifest"
        );
        assert_eq!(calls(), 3, "commit, then one fsync per durable removal");
        assert_eq!(fs::read(&operator)?, b"keep");
        Ok(())
    }

    #[test]
    fn undurable_manifest_removal_keeps_the_artifact_it_names() -> TestResult {
        let dir = tempfile::tempdir()?;
        SYNC_CALLS.with(|count| count.set(0));
        let mut publication = Publication::with_sync(dir.path(), fail_every_sync);
        let (artifact, manifest) = stage(&mut publication, dir.path())?;
        assert!(publication.commit().is_err());
        assert!(!manifest.exists());
        assert!(
            artifact.exists(),
            "an artifact is never removed before its manifest's removal is durable"
        );
        assert_eq!(calls(), 2, "the failed fsync is not retried");
        Ok(())
    }

    #[test]
    fn committed_publication_keeps_both_files_and_never_replaces_an_entry() -> TestResult {
        let dir = tempfile::tempdir()?;
        let mut publication = Publication::new(dir.path());
        let (artifact, manifest) = stage(&mut publication, dir.path())?;
        publication.commit()?;
        assert_eq!(fs::read(&artifact)?, b"artifact");
        assert_eq!(fs::read(&manifest)?, b"{}");

        let mut again = Publication::new(dir.path());
        let refused = again.create_new(&manifest);
        assert!(
            matches!(&refused, Err(IndexBundleError::ExistingBundle(path)) if *path == manifest),
            "create-new must refuse an existing manifest"
        );
        drop(refused);
        drop(again);
        assert_eq!(
            fs::read(&manifest)?,
            b"{}",
            "a refused create leaves the existing entry untouched"
        );
        assert_eq!(fs::read(&artifact)?, b"artifact");
        Ok(())
    }
}
