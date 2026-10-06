// LZ4 report projection reuses the canonical structural index and existing segment policy.
impl<'a, 'py> ReportContext<'a, 'py> {
    fn lz4_module(&mut self, tar: bool, read_budget: u64) -> PyResult<Evidence<'py>> {
        let py = self.py;
        let format = if tar { "tar.lz4" } else { "lz4" };
        let mut rows = self.embedded("lz4", true)?;
        if rows.is_empty() {
            let Ok(prefix) = self.view.reader.read_cached_at(0, 4) else {
                return Ok(Evidence::not_found(py, format));
            };
            if !crate::formats::lz4::leading(prefix.as_slice()) {
                return Ok(Evidence::not_found(py, format));
            }
            let facts = match &self.stream_structure {
                Some(Some(facts)) => facts.clone(),
                _ => {
                    let reader = self.view.reader.clone();
                    let index = py.detach(|| crate::formats::lz4::walk(&reader, 0, reader.len()));
                    let facts = index.to_dict(py, reader.len())?;
                    self.stream_structure = Some(Some(facts.clone()));
                    facts
                }
            };
            if u64_of(&facts, "structure.stream_count")? == 0
                && matches!(
                    str_of(&facts, "error")?.as_str(),
                    "" | "lz4_magic_not_found"
                )
            {
                return Ok(Evidence::not_found(py, format));
            }
            let row = facts.copy()?;
            row.set_item("offset", 0)?;
            row.set_item("end_offset", facts.get_item("segment_end")?)?;
            row.set_item(
                "extractable",
                truthy(&facts, "structure_validation_complete")?,
            )?;
            rows.push(row);
        }
        let details = PyDict::new(py);
        details.set_item("source", "embedded_scan")?;
        details.set_item("candidate_kind", "logical_archive")?;
        details.set_item("lz4", self.lz4_dictionaries.to_dict(py)?)?;
        let plans = PyDict::new(py);
        let mut segments = Vec::new();
        let mut blocked = false;
        let mut information_required = false;
        for row in &rows {
            let Some(plan) = dict_item(row, "stream_plan")? else {
                continue;
            };
            let offset = u64_of(row, "offset")?;
            let end = opt_u64_of(row, "end_offset")?;
            let ids = plan
                .get_item("dictionary_ids")?
                .map(|v| v.extract::<Vec<u32>>())
                .transpose()?
                .unwrap_or_default();
            let missing: Vec<u32> = ids
                .into_iter()
                .filter(|id| *id != 0 && !self.lz4_dictionaries.by_id.contains_key(id))
                .collect();
            let complete = truthy(&plan, "complete")?;
            let info = !missing.is_empty() || truthy(row, "information_required")?;
            if tar {
                if !complete || info {
                    continue;
                }
                let mut reader = self.view.reader.stream_cursor();
                std::io::Seek::seek(&mut reader, std::io::SeekFrom::Start(offset))?;
                let dictionary = self.lz4_dictionaries.clone();
                let sample = py.detach(|| {
                    crate::formats::lz4::sample_seekable(
                        reader,
                        1024,
                        end.unwrap_or(self.view.reader.len()) - offset,
                        read_budget,
                        &dictionary,
                    )
                });
                let Ok(sample) = sample else {
                    continue;
                };
                if sample.len() < 512 || !tar_header_plausible(&sample[..512]).0 {
                    continue;
                }
            }
            let mut flags = Vec::new();
            if info {
                flags.push("information_required".to_string());
            }
            if !missing.is_empty() {
                flags.push("lz4_dictionary_required".to_string());
            }
            let error = str_of(row, "error")?;
            if !error.is_empty() {
                flags.push(error);
            }
            let confidence = if complete && !info {
                if tar {
                    0.99
                } else {
                    0.98
                }
            } else {
                0.72
            };
            segments.push(Segment::new(
                offset,
                end,
                confidence,
                flags,
                vec!["lz4:frame_structure".to_string()],
            ));
            let plan = plan.copy()?;
            plan.set_item("missing_dictionary_ids", missing)?;
            plans.set_item(offset.to_string(), &plan)?;
            if offset == 0 {
                details.set_item("stream_plan", &plan)?;
            }
            blocked |= info || !complete;
            information_required |= info;
        }
        if segments.is_empty() {
            return Ok(Evidence::not_found(py, format));
        }
        details.set_item("stream_plans", plans)?;
        details.set_item("candidates", pyo3::types::PyList::new(py, &rows)?)?;
        details.set_item("information_required", information_required)?;
        Ok(Evidence::new(
            format,
            if blocked {
                0.72
            } else {
                if tar {
                    0.99
                } else {
                    0.98
                }
            },
            if blocked { "damaged" } else { "extractable" },
            segments,
            details,
        ))
    }
}
