//! Binary worker envelopes and typed manifest and trace chunks.
use super::worker_wire::{frame_payload, protocol_error, Decoder};
use crate::pipeline::{RecoveryFile, RecoveryPreview, RecoveryStatus};
use crate::scan::directory::{NativeWorkerManifest, OutputFileRecord};
use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::{fmt, io};

const PREVIEW_FILES: usize = 50;

#[derive(Default)]
struct TraceCounts {
    items: usize,
    preview: RecoveryPreview,
}

impl TraceCounts {
    fn merge(&mut self, chunk: Self) {
        self.items += chunk.items;
        self.preview.complete_files += chunk.preview.complete_files;
        self.preview.partial_files += chunk.preview.partial_files;
        self.preview.failed_files += chunk.preview.failed_files;
        self.preview.incomplete_files += chunk.preview.incomplete_files;
        // Main exposes the first 50 non-directory trace entries, in worker
        // order. Keep only that prefix while counting every reported member.
        let remaining = PREVIEW_FILES.saturating_sub(self.preview.files.len());
        self.preview.files.extend(chunk.preview.files.into_iter().take(remaining));
    }

    fn finish(mut self) -> RecoveryPreview {
        let preview = &mut self.preview;
        let count = preview.complete_files
            + preview.partial_files
            + preview.failed_files
            + preview.incomplete_files;
        preview.omitted_files = count - preview.files.len();
        self.preview
    }
}

impl<'de> Deserialize<'de> for TraceCounts {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Item<'a> {
            index: u32,
            path: &'a str,
            output_path: &'a str,
            is_dir: bool,
            #[serde(rename = "encrypted")]
            _encrypted: bool,
            bytes_written: u64,
            expected_size: u64,
            has_expected_size: bool,
            #[serde(rename = "source_crc32")]
            _source_crc32: u32,
            #[serde(rename = "has_source_crc32")]
            _has_source_crc32: bool,
            #[serde(rename = "output_crc32")]
            _output_crc32: u32,
            #[serde(rename = "has_output_crc32")]
            _has_output_crc32: bool,
            #[serde(rename = "crc_verified")]
            _crc_verified: bool,
            operation_result: i64,
            #[serde(rename = "operation_result_name")]
            _operation_result_name: &'a str,
            #[serde(rename = "hresult")]
            _hresult: i64,
            #[serde(rename = "win32_error")]
            _win32_error: i64,
            done: bool,
            failed: bool,
        }

        struct TraceVisitor;
        impl<'de> Visitor<'de> for TraceVisitor {
            type Value = TraceCounts;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("worker output trace items")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<TraceCounts, A::Error> {
                let mut trace = TraceCounts::default();
                while let Some(item) = seq.next_element::<Item>()? {
                    trace.items += 1;
                    if item.is_dir {
                        continue;
                    }
                    let status = if item.done && !item.failed && item.operation_result == 0 {
                        trace.preview.complete_files += 1;
                        RecoveryStatus::Complete
                    } else if item.bytes_written != 0 {
                        trace.preview.partial_files += 1;
                        RecoveryStatus::Partial
                    } else if item.failed || (item.done && item.operation_result != 0) {
                        trace.preview.failed_files += 1;
                        RecoveryStatus::Failed
                    } else {
                        trace.preview.incomplete_files += 1;
                        RecoveryStatus::Incomplete
                    };
                    if trace.preview.files.len() < PREVIEW_FILES {
                        trace.preview.files.push(RecoveryFile {
                            index: item.index,
                            path: item.path.to_owned(),
                            output_path: (!item.output_path.is_empty()
                                && item.output_path != item.path)
                                .then(|| item.output_path.to_owned()),
                            status,
                            bytes_written: item.bytes_written,
                            expected_size: item.has_expected_size.then_some(item.expected_size),
                        });
                    }
                }
                Ok(trace)
            }
        }

        deserializer.deserialize_seq(TraceVisitor)
    }
}

enum ChunkData {
    Manifest(Vec<OutputFileRecord>),
    Trace(TraceCounts),
}

pub(crate) struct WorkerFrame {
    pub(crate) summary: Value,
    pub(crate) manifest: Option<NativeWorkerManifest>,
    pub(crate) recovery: Option<RecoveryPreview>,
    chunk: Option<ChunkData>,
    manifest_summary: Option<ManifestSummary>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestSummary {
    complete: bool,
    file_count: usize,
    total_size: u64,
    chunk_count: usize,
}

impl WorkerFrame {
    fn envelope(summary: Value) -> Self {
        Self {
            summary,
            manifest: None,
            recovery: None,
            chunk: None,
            manifest_summary: None,
        }
    }
}

impl<'de> Deserialize<'de> for WorkerFrame {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct EnvelopeVisitor;
        impl<'de> Visitor<'de> for EnvelopeVisitor {
            type Value = WorkerFrame;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("worker event object")
            }

            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<WorkerFrame, A::Error> {
                let mut fields = Map::new();
                let mut chunk = None;
                let mut manifest_summary = None;
                while let Some(key) = map.next_key::<&str>()? {
                    let decoded = match key {
                        "rows" => ChunkData::Manifest(map.next_value::<WorkerRows>()?.0),
                        "items" => ChunkData::Trace(map.next_value()?),
                        "verified_manifest" => {
                            if manifest_summary.is_some() {
                                return Err(de::Error::duplicate_field("verified_manifest"));
                            }
                            manifest_summary = Some(map.next_value()?);
                            continue;
                        }
                        "diagnostics" => {
                            let section = map.next_value_seed(SummarySection::Diagnostics)?;
                            fields.insert(key.to_owned(), Value::Object(section));
                            continue;
                        }
                        _ => {
                            fields.insert(key.to_owned(), map.next_value::<Value>()?);
                            continue;
                        }
                    };
                    if chunk.replace(decoded).is_some() {
                        return Err(de::Error::custom("worker event contains multiple chunks"));
                    }
                }

                let mut frame = WorkerFrame::envelope(Value::Object(fields));
                frame.chunk = chunk;
                frame.manifest_summary = manifest_summary;
                Ok(frame)
            }
        }

        deserializer.deserialize_map(EnvelopeVisitor)
    }
}

#[derive(Clone, Copy)]
enum SummarySection {
    Diagnostics,
    Trace,
}

impl<'de> DeserializeSeed<'de> for SummarySection {
    type Value = Map<String, Value>;

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<Self::Value, D::Error> {
        deserializer.deserialize_map(self)
    }
}

impl<'de> Visitor<'de> for SummarySection {
    type Value = Map<String, Value>;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("worker result summary")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
        let mut fields = Map::new();
        while let Some(key) = map.next_key::<&str>()? {
            let value = match (self, key) {
                (Self::Trace, "items") => {
                    return Err(de::Error::custom(
                        "worker result details must arrive in chunks",
                    ));
                }
                (Self::Diagnostics, "output_trace") => {
                    Value::Object(map.next_value_seed(Self::Trace)?)
                }
                _ => map.next_value::<Value>()?,
            };
            fields.insert(key.to_owned(), value);
        }
        Ok(fields)
    }
}

/// A valid frame boundary lets a bad job body fail only the affected job.
pub(crate) fn parse_worker_transport_event(frame: &[u8]) -> io::Result<WorkerFrame> {
    let data = frame_payload(frame)?;
    let mut decoder = Decoder::new(data);
    let event = WorkerFrame::deserialize(&mut decoder)
        .map_err(io::Error::from)
        .and_then(|event| {
            if !decoder.data.is_empty() {
                return Err(protocol_error("trailing worker value"));
            }
            Ok(event)
        });
    match event {
        Ok(event) => Ok(event),
        Err(error) => {
            let job_id = Decoder::new(data)
                .routing_job_id()
                .ok()
                .filter(|id| !id.is_empty())
                .ok_or_else(|| {
                    protocol_error(format!("unattributable worker protocol error: {error}"))
                })?;
            Ok(WorkerFrame::envelope(json!({
                "type": "protocol_error",
                "job_id": job_id,
                "message": format!("malformed worker event: {error}"),
            })))
        }
    }
}

pub(crate) struct NativeWorkerResultAccumulator {
    job_id: String,
    manifest_seq: usize,
    trace_seq: usize,
    files: Vec<OutputFileRecord>,
    trace: TraceCounts,
    finished: bool,
}

impl NativeWorkerResultAccumulator {
    pub(crate) fn new(job_id: String) -> Self {
        Self {
            job_id,
            manifest_seq: 0,
            trace_seq: 0,
            files: Vec::new(),
            trace: TraceCounts::default(),
            finished: false,
        }
    }

    /// Chunks are consumed. A result moves the accumulated tables into its envelope.
    pub(crate) fn accept(&mut self, mut frame: WorkerFrame) -> io::Result<Option<WorkerFrame>> {
        let payload = &mut frame.summary;
        let kind = payload
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| protocol_error("worker event type missing"))?;
        if !matches!(kind, "manifest_chunk" | "trace_chunk" | "result") {
            return Ok(Some(frame));
        }
        if self.finished {
            return Err(protocol_error("worker data received after result"));
        }
        if payload.get("job_id").and_then(Value::as_str) != Some(self.job_id.as_str()) {
            return Err(protocol_error("worker chunk belongs to another job"));
        }
        if kind != "result" {
            let seq = count(payload, "seq")?;
            let expected = if kind == "manifest_chunk" {
                self.manifest_seq
            } else {
                self.trace_seq
            };
            if seq != expected {
                return Err(protocol_error(format!(
                    "{kind} sequence {seq}, expected {expected}"
                )));
            }
            match frame.chunk {
                Some(ChunkData::Manifest(files)) if kind == "manifest_chunk" => {
                    append_chunk(&mut self.files, files);
                    self.manifest_seq += 1;
                }
                Some(ChunkData::Trace(trace)) if kind == "trace_chunk" => {
                    self.trace.merge(trace);
                    self.trace_seq += 1;
                }
                _ => return Err(protocol_error("worker chunk data type mismatch")),
            }
            return Ok(None);
        }

        let trace = payload
            .get("diagnostics")
            .and_then(|d| d.get("output_trace"));
        check_chunk_summary(trace, self.trace_seq, self.trace.items, "item_count")?;
        match frame.manifest_summary.take() {
            Some(summary) if summary.chunk_count == self.manifest_seq
                && summary.file_count == self.files.len() => {
                frame.manifest = Some(NativeWorkerManifest::from_parts(
                    std::mem::take(&mut self.files), summary.complete, summary.total_size,
                ));
            }
            None if self.manifest_seq == 0 => {}
            _ => return Err(protocol_error("worker manifest chunk summary count mismatch")),
        }
        if let Some(trace) = payload
            .get_mut("diagnostics")
            .and_then(|d| d.get_mut("output_trace"))
            .and_then(Value::as_object_mut)
        {
            if self.trace.items != 0 {
                frame.recovery = Some(std::mem::take(&mut self.trace).finish());
            }
            trace.remove("chunk_count");
            trace.remove("item_count");
        }
        self.finished = true;
        Ok(Some(frame))
    }
}

fn append_chunk<T>(table: &mut Vec<T>, mut chunk: Vec<T>) {
    if table.is_empty() {
        *table = chunk;
    } else {
        table.append(&mut chunk);
    }
}

fn count(value: &Value, key: &str) -> io::Result<usize> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or_else(|| protocol_error(format!("missing or invalid worker field {key}")))
}

fn check_chunk_summary(
    summary: Option<&Value>,
    chunks: usize,
    rows: usize,
    count_key: &str,
) -> io::Result<()> {
    match summary {
        Some(summary)
            if count(summary, "chunk_count")? == chunks && count(summary, count_key)? == rows =>
        {
            Ok(())
        }
        None if chunks == 0 => Ok(()),
        _ => Err(protocol_error("worker chunk summary count mismatch")),
    }
}

/// One output path, size, status, optional mtime, and magic prefix per file.
struct WorkerRows(Vec<OutputFileRecord>);

type WorkerRow<'a> = (&'a str, u64, u8, Option<u64>, MagicBytes);

impl<'de> Deserialize<'de> for WorkerRows {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RowsVisitor;

        impl<'de> Visitor<'de> for RowsVisitor {
            type Value = WorkerRows;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("worker manifest rows")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<WorkerRows, A::Error> {
                let mut files = Vec::with_capacity(seq.size_hint().unwrap_or(0));
                while let Some((path, size, status, mtime_ns, magic)) =
                    seq.next_element::<WorkerRow<'de>>()?
                {
                    files.push(OutputFileRecord {
                        path: path.to_owned(),
                        size,
                        status,
                        mtime_ns,
                        magic: magic.0,
                    });
                }
                Ok(WorkerRows(files))
            }
        }

        deserializer.deserialize_seq(RowsVisitor)
    }
}

struct MagicBytes(Box<[u8]>);
impl<'de> Deserialize<'de> for MagicBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BytesVisitor;
        impl<'de> Visitor<'de> for BytesVisitor {
            type Value = MagicBytes;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("worker magic bytes")
            }
            fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<MagicBytes, E> {
                Ok(MagicBytes(bytes.into()))
            }
        }
        deserializer.deserialize_bytes(BytesVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::worker_wire::encode_worker_frame;

    fn manifest_frame(job: &str) -> WorkerFrame {
        let sentinel = "__binary_magic__";
        let mut bytes = encode_worker_frame(&json!({
            "type": "manifest_chunk", "job_id": job, "seq": 0,
            "rows": [[format!("{job}-renamed.txt"), 3, 1, 123, sentinel]],
        }))
        .unwrap();
        let body = bytes
            .windows(sentinel.len())
            .position(|part| part == sentinel.as_bytes())
            .unwrap();
        bytes.splice(
            body - 5..body + sentinel.len(),
            [8, 3, 0, 0, 0, b'a', b'b', b'c'],
        );
        let size = (bytes.len() - 8) as u32;
        bytes[4..8].copy_from_slice(&size.to_le_bytes());
        parse_worker_transport_event(&bytes).unwrap()
    }

    fn result_frame(job: &str, files: u64) -> WorkerFrame {
        parse_worker_transport_event(
            &encode_worker_frame(&json!({
                "type": "result", "job_id": job,
                "verified_manifest": {
                    "file_count": files, "complete": true, "total_size": 3,
                    "chunk_count": 1,
                },
            }))
            .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn worker_chunks_move_into_their_own_result_only() {
        let mut first = NativeWorkerResultAccumulator::new("first".into());
        let mut second = NativeWorkerResultAccumulator::new("second".into());
        assert!(second.accept(manifest_frame("second")).unwrap().is_none());
        assert!(first.accept(manifest_frame("first")).unwrap().is_none());
        let Err(duplicate) = first.accept(manifest_frame("first")) else {
            panic!("duplicate chunk")
        };
        assert!(duplicate.to_string().contains("sequence"));
        let Err(mismatch) = first.accept(result_frame("first", 2)) else {
            panic!("bad count")
        };
        assert!(mismatch.to_string().contains("count mismatch"));
        for (job, accumulator) in [("first", first), ("second", second)] {
            let manifest = { accumulator }
                .accept(result_frame(job, 1))
                .unwrap()
                .unwrap()
                .manifest
                .unwrap();
            assert!(manifest.complete());
            let row = &manifest.records()[0];
            assert_eq!(row.path, format!("{job}-renamed.txt"));
            assert_eq!(&*row.magic, b"abc");
            assert_eq!(row.mtime_ns, Some(123));
        }
    }

    #[test]
    fn trace_preview_keeps_main_prefix_across_chunks() {
        let mut trace = TraceCounts::default();
        for range in [0..55, 55..60] {
            let items = range.map(|position| {
                let failed = position >= 50 && position != 59;
                json!({
                    "index": 100 - position, "path": format!("file-{position}"),
                    "output_path": "", "is_dir": false, "encrypted": false,
                    "bytes_written": if position < 50 { 1 } else { 0 },
                    "expected_size": 1, "has_expected_size": true,
                    "source_crc32": 0, "has_source_crc32": false,
                    "output_crc32": 0, "has_output_crc32": false, "crc_verified": false,
                    "operation_result": if position >= 50 { 1 } else { 0 },
                    "operation_result_name": "", "hresult": 0, "win32_error": 0,
                    "done": position != 59, "failed": failed,
                })
            }).collect::<Vec<_>>();
            // Parsing also verifies the prefix bound before chunk merging and
            // main's unfinished/nonzero-result classification (last member).
            trace.merge(serde_json::from_str(&serde_json::to_string(&items).unwrap()).unwrap());
        }
        assert_eq!(trace.items, 60);
        let preview = trace.finish();
        assert_eq!(preview.complete_files, 50);
        assert_eq!(preview.failed_files, 9);
        assert_eq!(preview.incomplete_files, 1);
        assert_eq!(preview.omitted_files, 10);
        assert_eq!(preview.files.iter().map(|file| file.path.clone()).collect::<Vec<_>>(),
            (0..50).map(|position| format!("file-{position}")).collect::<Vec<_>>());
    }

    #[test]
    fn malformed_job_body_does_not_break_frame_routing() {
        let malformed = encode_worker_frame(&json!({
            "type": "result", "job_id": "malformed",
            "diagnostics": {"output_trace": {"items": []}},
        }))
        .unwrap();
        let event = parse_worker_transport_event(&malformed).unwrap();
        assert_eq!(event.summary["type"], "protocol_error");
        assert_eq!(event.summary["job_id"], "malformed");
        assert!(parse_worker_transport_event(b"broken stream").is_err());
    }
}
