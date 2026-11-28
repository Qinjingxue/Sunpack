use super::{Layer, ManagedReader, ProbeBytes, ProbeShape, ReadView, Span};
use std::io;

pub(super) const PROBE: ProbeShape = ProbeShape { minimum: 6, prefix: 0, suffix: 4 };

pub(super) fn accepts(size: u64, _: &[u8], suffix: &[u8]) -> bool {
    apate_geometry(size, suffix.try_into().unwrap()).is_some()
}

pub(super) fn layer(file: &ManagedReader, previous: Option<&ReadView>, size: u64, evidence: Option<ProbeBytes>) -> io::Result<Option<Layer>> {
    let mut footer = [0; 4];
    let read = |at, dest: &mut [u8]| file.read_direct_into_at(at, dest);
    if let Some(bytes) = evidence {
        footer.copy_from_slice(bytes.suffix);
    } else if let Some(view) = previous {
        view.read_with(size - 4, &mut footer, read)?;
    } else if read(size - 4, &mut footer)? != footer.len() {
        return Err(io::ErrorKind::UnexpectedEof.into());
    }
    let Some((mask, len)) = apate_geometry(size, footer) else { return Ok(None) };
    let head = len.min(mask);
    let mut spans = Vec::with_capacity(previous.map_or(2, |v| v.spans.len() + 1));
    if let Some(previous) = previous {
        previous.visit(size - 4 - head, size - 4, |mut span| {
            span.reverse = !span.reverse;
            spans.push(span);
            Ok(())
        })?;
        spans.reverse();
        if len > mask {
            previous.visit(mask, len, |span| {
                span.append_to(&mut spans);
                Ok(())
            })?;
        }
    } else {
        spans.push(Span {
            start: size - 4 - head,
            end: size - 4,
            reverse: true,
        });
        if len > mask {
            spans.push(Span {
                start: mask,
                end: len,
                reverse: false,
            });
        }
    }
    Ok(Some(Layer { size: len, spans, prefix_end: Some(mask) }))
}

/// The official custom mask loader requires a positive length below Int32.MaxValue / 7.
fn apate_geometry(size: u64, footer: [u8; 4]) -> Option<(u64, u64)> {
    let mask = i32::from_le_bytes(footer);
    if !(1..i32::MAX / 7).contains(&mask) {
        return None;
    }
    let mask = mask as u64;
    let len = size.checked_sub(4 + mask)?;
    (len != 0).then_some((mask, len))
}
