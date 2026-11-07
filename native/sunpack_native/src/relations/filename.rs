use super::{first_dot_stem, logical_name_from_parsed, parse_volume_candidates, ParsedVolume};
use crate::path_keys::case_key;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub(super) struct NumberOccurrence {
    pub value: u32,
    pub width: usize,
    pub left: String,
    pub right: String,
    pub ordinal: usize,
}

#[derive(Debug, Clone, Default)]
pub(super) struct NameFeatures {
    pub numbers: Vec<NumberOccurrence>,
    pub canonical: Vec<ParsedVolume>,
}

impl NameFeatures {
    pub fn parse(name: &str) -> Self {
        let lower = name.to_ascii_lowercase();
        let suffix = lower
            .split_once('.')
            .map_or(lower.as_str(), |(_, suffix)| suffix);
        let bytes = suffix.as_bytes();
        let mut numbers = Vec::new();
        let mut ordinals = HashMap::new();
        let mut cursor = 0;
        while cursor < bytes.len() {
            if !bytes[cursor].is_ascii_digit() {
                cursor += 1;
                continue;
            }
            let start = cursor;
            while cursor < bytes.len() && bytes[cursor].is_ascii_digit() {
                cursor += 1;
            }
            let Some(value) = suffix[start..cursor].parse().ok() else {
                continue;
            };
            // Context is the adjacent token text, not its absolute byte position.
            // Other numeric channels may vary independently (including their width).
            let left_start = bytes[..start]
                .iter()
                .rposition(|b| !b.is_ascii_alphabetic())
                .map_or(0, |i| i + 1);
            let right_end = bytes[cursor..]
                .iter()
                .position(|b| !b.is_ascii_alphabetic())
                .map_or(bytes.len(), |i| cursor + i);
            let left = &suffix[left_start..start];
            let right = &suffix[cursor..right_end];
            let ordinal = ordinals.entry((left, right)).or_insert(0usize);
            numbers.push(NumberOccurrence {
                value,
                width: cursor - start,
                left: left.to_owned(),
                right: right.to_owned(),
                ordinal: *ordinal,
            });
            *ordinal += 1;
        }
        Self {
            numbers,
            canonical: parse_volume_candidates(name),
        }
    }

    pub fn family(&self, format: &str) -> Option<String> {
        self.canonical
            .iter()
            .find(|p| p.family == format)
            .map(logical_name_from_parsed)
            .map(|s| case_key(&s))
    }
}

/// Family-local fixed fields. Borrows the cached, unmodified filename facts;
/// watch membership changes and password retries must rebuild this small view.
/// One pass over numeric occurrences; no substring comparisons or name copies.
pub(super) struct NameProfile<'a> {
    fields: HashMap<(usize, &'a str, &'a str), (u32, bool, bool)>,
}

impl<'a> NameProfile<'a> {
    pub fn new(names: impl Iterator<Item = &'a NameFeatures>) -> Self {
        let mut fields = HashMap::new();
        for name in names {
            for n in &name.numbers {
                fields
                    .entry((n.ordinal, n.left.as_str(), n.right.as_str()))
                    .and_modify(|(value, repeated, varied): &mut (u32, bool, bool)| {
                        *repeated = true;
                        *varied |= *value != n.value;
                    })
                    .or_insert((n.value, false, false));
            }
        }
        Self { fields }
    }

    pub fn active(&self, n: &NumberOccurrence) -> bool {
        self.active_field(n.ordinal, &n.left, &n.right)
    }

    fn active_field(&self, ordinal: usize, left: &str, right: &str) -> bool {
        self.fields
            .get(&(ordinal, left, right))
            .is_none_or(|(_, repeated, varied)| !repeated || *varied)
    }

    pub fn number(&self, channel: &NumberChannel, name: &NameFeatures) -> Option<u32> {
        let value = channel.number(name)?;
        if let NumberChannel::Token {
            ordinal,
            left,
            right,
        } = channel
        {
            return self.active_field(*ordinal, left, right).then_some(value);
        }
        // Canonical and token channels share the same constant-field mask.
        name.numbers
            .iter()
            .any(|n| n.value == value && self.active(n))
            .then_some(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum NumberChannel {
    RarPart,
    Canonical {
        format: String,
        style: String,
        family: Option<String>,
    },
    Token {
        ordinal: usize,
        left: String,
        right: String,
    },
}

impl NumberChannel {
    pub fn number(&self, features: &NameFeatures) -> Option<u32> {
        match self {
            Self::RarPart => {
                let mut found = features
                    .numbers
                    .iter()
                    .filter(|n| n.left == "part" && n.value > 0);
                let value = found.next()?.value;
                found.all(|n| n.value == value).then_some(value)
            }
            Self::Canonical {
                format,
                style,
                family,
            } => {
                let mut found = features.canonical.iter().filter(|p| {
                    p.family == format
                        && (p.style == style
                            || (format == "rar"
                                && style == "rar_part"
                                && p.style == "rar_sfx_part"))
                        && family
                            .as_ref()
                            .is_none_or(|f| case_key(&logical_name_from_parsed(p)) == *f)
                });
                let value = found.next()?.number;
                found.all(|p| p.number == value).then_some(value)
            }
            Self::Token {
                ordinal,
                left,
                right,
            } => features.numbers.iter().find_map(|n| {
                (n.ordinal == *ordinal && n.left == *left && n.right == *right).then_some(n.value)
            }),
        }
    }

    pub fn tokens(features: &NameFeatures) -> impl Iterator<Item = Self> + '_ {
        features.numbers.iter().map(|n| Self::Token {
            ordinal: n.ordinal,
            left: n.left.clone(),
            right: n.right.clone(),
        })
    }
}

pub(super) fn logical_name(name: &str, features: &NameFeatures, format: &str) -> String {
    features
        .family(format)
        .unwrap_or_else(|| case_key(first_dot_stem(name)))
}
