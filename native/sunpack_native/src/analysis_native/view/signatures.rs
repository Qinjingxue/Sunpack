struct LeadingSignatures {
    head: crate::io::reader::CachedBytes,
    rar: bool,
    seven_zip: bool,
    zip_local: Option<u64>,
    zip_eocd: Option<(u64, [u8; 22])>,
}

impl LeadingSignatures {
    fn read(reader: &ManagedReader) -> io::Result<Self> {
        let prefix = reader.read_cached_at(0, 32)?;
        let head = prefix.as_slice();
        let split_zip = head.starts_with(b"PK\x07\x08") || head.starts_with(b"PK00");
        let zip_local = if head.starts_with(ZIP_LOCAL) {
            Some(0)
        } else if split_zip && head.get(4..8) == Some(ZIP_LOCAL) {
            Some(4)
        } else {
            None
        };
        let zip_eocd = if zip_local.is_some()
            || split_zip
            || head.starts_with(ZIP_EOCD)
            || head.starts_with(ZIP64_EOCD)
        {
            let mut bytes_read = 0;
            let (tail, tail_start) =
                crate::formats::zip::read_eocd_tail(reader, 0, reader.len(), head, &mut bytes_read)?;
            // Arbitrary suffixes belong to embedded discovery. Only the EOCD
            // and its declared comment may terminate an ordinary ZIP input.
            crate::formats::zip::find_eocd_record(&tail, false).map(|eocd| {
                (
                    tail_start + eocd.offset as u64,
                    tail[eocd.offset..eocd.offset + 22].try_into().unwrap(),
                )
            })
        } else {
            None
        };
        Ok(Self {
            rar: head.starts_with(RAR4) || head.starts_with(RAR5),
            seven_zip: head.starts_with(SEVEN_ZIP),
            zip_local,
            zip_eocd,
            head: prefix,
        })
    }
}
