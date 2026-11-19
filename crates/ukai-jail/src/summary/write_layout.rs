//! Summarize runs of identical-shaped audit writes. Fixed portions are compared
//! byte for byte with a fully decoded frame. A mismatch hands the entire block
//! back to the ordinary decoder, including its prefix/error accounting.
use super::{Frame, PathValue, Scan, Str};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::borrow::Cow;

#[derive(Deserialize)]
struct Locations<'a> {
    #[serde(borrow)]
    source_seq: &'a RawValue,
    #[serde(borrow)]
    observed_at: &'a RawValue,
    #[serde(borrow)]
    monotonic_ns: &'a RawValue,
    #[serde(borrow)]
    fields: Fields<'a>,
}
#[derive(Deserialize)]
struct Fields<'a> {
    #[serde(borrow)]
    path: Path<'a>,
}
#[derive(Deserialize)]
struct Path<'a> {
    #[serde(borrow)]
    value: &'a RawValue,
}

#[derive(Clone, Copy)]
enum Slot {
    Sequence,
    Clock,
    Path,
}

struct Layout<'a> {
    parts: [(&'a str, Slot); 4],
    tail: &'a str,
    change: u8,
}
impl<'a> Layout<'a> {
    fn new(line: &'a str, attempt: &str) -> Option<Self> {
        let frame: Frame = serde_json::from_str(line).ok()?;
        let fields = frame.fields.as_ref()?;
        if frame.attempt_id.as_deref() != Some(attempt)
            || frame.source.as_deref() != Some("audit")
            || !matches!(
                frame.operation.as_deref(),
                Some("fs.create" | "fs.write" | "fs.unlink")
            )
            || fields.path2.is_some()
        {
            return None;
        }
        let path = fields.path.as_ref()?;
        if &*path.kind != "workspace_relative" {
            return None;
        }
        let PathValue::Text(Str(Cow::Borrowed(value))) = path.value.as_ref()? else {
            return None;
        };
        // Classify the representative event with the same policy as the
        // serial scanner. A batch represents exactly one named write effect.
        let mut sample = Scan::default();
        sample.add(&frame);
        let change = *sample.paths.text.get(*value)?;
        let loc: Locations = serde_json::from_str(line).ok()?;
        // The layout and summary decoders must have selected the same path.
        if loc.fields.path.value.get().get(1..)?.as_ptr() != value.as_ptr() {
            return None;
        }
        let mut tokens = [
            (loc.source_seq, Slot::Sequence),
            (loc.observed_at, Slot::Clock),
            (loc.monotonic_ns, Slot::Clock),
            (loc.fields.path.value, Slot::Path),
        ];
        tokens.sort_unstable_by_key(|(v, _)| v.get().as_ptr() as usize);
        let mut parts = [("", Slot::Sequence); 4];
        let mut end = 0;
        for (part, (v, slot)) in parts.iter_mut().zip(tokens) {
            let raw = v.get();
            let start = (raw.as_ptr() as usize).checked_sub(line.as_ptr() as usize)?;
            *part = (line.get(end..start)?, slot);
            end = start.checked_add(raw.len())?;
        }
        Some(Self {
            parts,
            tail: line.get(end..)?,
            change,
        })
    }

    fn read<'b>(&self, mut line: &'b str) -> Option<(u64, &'b str)> {
        if line.len() >= crate::journal::FRAME_MAX {
            return None;
        }
        let (mut seq, mut path) = (0, "");
        for (fixed, slot) in self.parts {
            line = line.strip_prefix(fixed)?;
            match slot {
                Slot::Sequence => {
                    let len = line.bytes().position(|c| !c.is_ascii_digit())?;
                    let digits = &line[..len];
                    if digits.len() > 1 && digits.starts_with('0') {
                        return None;
                    }
                    seq = digits.parse().ok()?;
                    line = &line[len..];
                }
                Slot::Clock | Slot::Path => {
                    let body = line.strip_prefix('"')?;
                    let (value, rest) = body.split_once('"')?;
                    if value.bytes().any(|c| c < 32 || c == b'\\') {
                        return None;
                    }
                    if matches!(slot, Slot::Path) {
                        path = value;
                    }
                    line = rest;
                }
            }
        }
        (line == self.tail).then_some((seq, path))
    }
}

struct Batch<'a> {
    change: u8,
    first: u64,
    last: u64,
    paths: Vec<&'a str>,
}

impl<'a> Batch<'a> {
    fn parse(block: &'a [u8], attempt: &str) -> Option<Self> {
        let text = std::str::from_utf8(block).ok()?.strip_suffix('\n')?;
        let mut lines = text.split('\n');
        let first_line = lines.next()?;
        if first_line.len() >= crate::journal::FRAME_MAX
            || !first_line.trim_ascii_start().starts_with('{')
        {
            return None;
        }
        let layout = Layout::new(first_line, attempt)?;
        let (first, path) = layout.read(first_line)?;
        let mut paths = Vec::with_capacity(text.len() / first_line.len());
        paths.push(path);
        let mut last = first;
        for line in lines {
            let (seq, path) = layout.read(line)?;
            if last.checked_add(1)? != seq {
                return None;
            }
            last = seq;
            paths.push(path);
        }
        Some(Self {
            first,
            last,
            paths,
            change: layout.change,
        })
    }

    fn apply(self, scan: &mut Scan<'a>) -> bool {
        let previous = scan.last_seq.get("audit").copied().unwrap_or(0);
        if self.first <= previous {
            return false;
        }
        if self.first != previous + 1 && !scan.loss_recorded {
            scan.unrecorded_hole = true;
        }
        scan.last_seq.insert("audit".to_owned(), self.last);
        scan.last_receipt_note = None;
        *scan.class_counts.entry("fs.write").or_insert(0) += self.paths.len() as u64;
        for path in self.paths {
            *scan.paths.text.entry(Cow::Borrowed(path)).or_insert(0) |= self.change;
        }
        true
    }
}

pub(super) fn scan<'a>(mut bytes: &'a [u8], attempt: &str) -> Scan<'a> {
    const BLOCK: usize = 64 * 1024;
    let mut result = Scan::default();
    if bytes.len() < 4 * BLOCK {
        super::scan_into(&mut result, bytes, attempt);
        return result;
    }
    let mut blocks = Vec::new();
    while bytes.len() > BLOCK {
        let Some(end) = memchr::memchr(b'\n', &bytes[BLOCK..]) else {
            break;
        };
        let (block, rest) = bytes.split_at(BLOCK + end + 1);
        blocks.push(block);
        bytes = rest;
    }
    if !bytes.is_empty() {
        blocks.push(bytes);
    }
    let mut batches: Vec<_> = (0..blocks.len()).map(|_| None).collect();
    let workers = std::thread::available_parallelism().map_or(1, |n| n.get().min(4));
    let group = blocks.len().div_ceil(workers);
    std::thread::scope(|scope| {
        for (input, output) in blocks.chunks(group).zip(batches.chunks_mut(group)) {
            // On a resource-constrained host a missing worker leaves its batch
            // empty. The caller decodes that block on the current thread.
            let _ = std::thread::Builder::new().spawn_scoped(scope, move || {
                for (block, batch) in input.iter().zip(output) {
                    *batch = Batch::parse(block, attempt);
                }
            });
        }
    });
    for (block, batch) in blocks.into_iter().zip(batches) {
        if !batch.is_some_and(|batch| batch.apply(&mut result)) {
            super::scan_into(&mut result, block, attempt);
            if result.broken {
                break;
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(seq: u64, name: &str) -> String {
        serde_json::json!({
            "attempt_id":"here", "source":"audit", "source_seq":seq,
            "monotonic_ns":seq.to_string(), "observed_at":"2026-01-01T12:00:00Z",
            "operation":"fs.write", "outcome":{"ok":true},
            "fields":{"path":{"kind":"workspace_relative","value":name},"action":"opened_for_mutation"}
        }).to_string() + "\n"
    }

    #[test]
    fn fast_writes_require_valid_tokens_and_one_increasing_sequence() {
        let first = write(1, "first");
        let valid = write(2, "café");
        let both = first.clone() + &valid;
        let batch = Batch::parse(both.as_bytes(), "here").unwrap();
        assert_eq!(batch.paths, ["first", "café"]);
        assert_eq!((batch.first, batch.last), (1, 2));
        for other in [
            write(1, "repeat"),
            write(4, "hole"),
            write(2, "with \"quotes\""),
            valid.replace("café", "c\tafé"),
            valid.replace("\"source_seq\":2", "\"source_seq\":02"),
            valid.replace("\"source_seq\":2", "\"source_seq\":18446744073709551616"),
            valid.replace("\"here\"", "\"there\""),
            valid.replace("\"ok\":true", "\"ok\":false"),
            valid.replace("\"path\":", "\"unused\":"),
            valid.trim_end().to_string(),
        ] {
            assert!(
                Batch::parse((first.clone() + &other).as_bytes(), "here").is_none(),
                "{other}"
            );
        }
    }

    #[test]
    fn distinct_write_actions_use_the_same_flags_as_the_record_reader() {
        for (op, action) in [
            ("fs.create", "created"),
            ("fs.unlink", "removed"),
            ("fs.write", "modified"),
            ("fs.write", "metadata_changed"),
            ("fs.write", "truncated"),
        ] {
            let text: String = (1..=10)
                .map(|seq| {
                    write(seq, "☃")
                        .replace("fs.write", op)
                        .replace("opened_for_mutation", action)
                })
                .collect();
            let data = text.as_bytes();
            let batch = Batch::parse(data, "here").unwrap();
            let mut actual = Scan::default();
            assert!(batch.apply(&mut actual));
            let mut expected = Scan::default();
            super::super::scan_into(&mut expected, data, "here");
            assert_eq!(actual, expected);
        }
        let mut damaged = write(1, "bad-path").into_bytes();
        let content = damaged.windows(8).position(|s| s == b"bad-path").unwrap();
        damaged[content] = 255;
        assert!(Batch::parse(&damaged, "here").is_none());
    }

    #[test]
    fn block_reduction_matches_the_serial_prefix_and_loss_accounting() {
        let prefix: String = (1..=1200)
            .map(|i| write(i, &format!("file/{}", i % 234)))
            .collect();
        let suffix: String = (1202..=2400)
            .map(|i| write(i, &format!("file/{}", i % 311)))
            .collect();
        for middle in [write(1201,"valid"), write(1200,"duplicate"), write(1202,"hole"),
                       write(1201,"escaped\\name"), write(1201,"other").replace("here","elsewhere"),
                       "{malformed}\n".to_owned(), "{\"source\":\"wrapper\",\"attempt_id\":\"here\",\"source_seq\":1,\"operation\":\"note\",\"fields\":{\"kind\":\"coverage_gap\",\"reason\":\"trace_transport_loss\"}}\n".to_owned()] {
            let bytes = [prefix.as_str(),middle.as_str(),suffix.as_str()].concat().into_bytes();
            for data in [&bytes[..],&bytes[..bytes.len()-1]] {
                let mut expected = Scan::default();
                super::super::scan_into(&mut expected,data,"here");
                assert_eq!(scan(data,"here"), expected);
            }
        }
    }
}
