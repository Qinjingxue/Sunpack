//! Binary worker envelopes and typed manifest chunks.
use super::worker_wire::{frame_payload, protocol_error, Decoder};
use crate::scan::directory::{NativeWorkerManifest, OutputFileRecord};
use serde::de::{self, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::{fmt, io};

pub(crate) struct WorkerFrame {
    pub(crate) summary: Value,
    pub(crate) manifest: Option<NativeWorkerManifest>,
    chunk: Option<Vec<OutputFileRecord>>,
    manifest_summary: Option<ManifestSummary>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestSummary {
    complete: bool,
    file_count: usize,
    total_size: u64,
    chunk_count: Option<usize>,
}

impl WorkerFrame {
    fn envelope(summary: Value) -> Self {
        Self {
            summary,
            manifest: None,
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
                    match key {
                        "rows" => {
                            if chunk.is_some() {
                                return Err(de::Error::duplicate_field("rows"));
                            }
                            chunk = Some(map.next_value::<WorkerRows>()?.0);
                        }
                        "verified_manifest" => {
                            if manifest_summary.is_some() {
                                return Err(de::Error::duplicate_field("verified_manifest"));
                            }
                            manifest_summary = Some(map.next_value()?);
                        }
                        _ => {
                            fields.insert(key.to_owned(), map.next_value::<Value>()?);
                        }
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
    files: Vec<OutputFileRecord>,
    finished: bool,
}

impl NativeWorkerResultAccumulator {
    pub(crate) fn new(job_id: String) -> Self {
        Self {
            job_id,
            manifest_seq: 0,
            files: Vec::new(),
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
        if !matches!(kind, "manifest_chunk" | "result") {
            return Ok(Some(frame));
        }
        if self.finished {
            return Err(protocol_error("worker data received after result"));
        }
        if payload.get("job_id").and_then(Value::as_str) != Some(self.job_id.as_str()) {
            return Err(protocol_error("worker chunk belongs to another job"));
        }
        if kind == "manifest_chunk" {
            let seq = count(payload, "seq")?;
            if seq != self.manifest_seq {
                return Err(protocol_error(format!(
                    "manifest chunk sequence {seq}, expected {}", self.manifest_seq
                )));
            }
            let files = frame.chunk.ok_or_else(|| protocol_error("worker manifest rows missing"))?;
            append_chunk(&mut self.files, files);
            self.manifest_seq += 1;
            return Ok(None);
        }

        match frame.manifest_summary.take() {
            Some(summary) if summary.chunk_count == Some(self.manifest_seq)
                && summary.file_count == self.files.len() => {
                frame.manifest = Some(NativeWorkerManifest::from_parts(
                    std::mem::take(&mut self.files), summary.complete, summary.total_size,
                ));
            }
            Some(summary) if summary.chunk_count.is_none() && self.manifest_seq == 0 => {
                frame.manifest = Some(NativeWorkerManifest::summary(
                    summary.file_count, summary.complete, summary.total_size,
                ));
            }
            None if self.manifest_seq == 0 => {}
            _ => return Err(protocol_error("worker manifest chunk summary count mismatch")),
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
#[path = "../../tests/unit/scan/worker_event/tests.rs"]
mod tests;
