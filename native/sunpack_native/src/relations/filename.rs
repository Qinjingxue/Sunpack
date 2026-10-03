use super::{first_dot_stem, logical_name_from_parsed, parse_volume_candidates, ParsedVolume};

#[derive(Debug, Clone)]
pub(super) struct NumberOccurrence {
    pub value: u32,
    pub width: usize,
    pub left: String,
    pub right: String,
    pub seven_zip_literal: bool,
}

#[derive(Debug, Clone, Default)]
pub(super) struct NameFeatures {
    pub numbers: Vec<NumberOccurrence>,
    pub canonical: Vec<ParsedVolume>,
}

impl NameFeatures {
    pub fn has_number_channel(&self, format: &str) -> bool {
        self.numbers
            .iter()
            .any(|n| !(format == "7z" && n.seven_zip_literal))
    }

    pub fn parse(name: &str) -> Self {
        let lower = name.to_ascii_lowercase();
        let suffix = lower
            .split_once('.')
            .map_or(lower.as_str(), |(_, suffix)| suffix);
        let bytes = suffix.as_bytes();
        let mut numbers = Vec::new();
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
            numbers.push(NumberOccurrence {
                value,
                width: cursor - start,
                left: suffix[left_start..start].to_owned(),
                right: suffix[cursor..right_end].to_owned(),
                seven_zip_literal: value == 7
                    && cursor == start + 1
                    && bytes.get(cursor) == Some(&b'z')
                    && (start == 0 || !bytes[start - 1].is_ascii_alphanumeric())
                    && bytes
                        .get(cursor + 1)
                        .is_none_or(|b| !b.is_ascii_alphanumeric()),
            });
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
            .map(|s| s.to_ascii_lowercase())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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
    pub fn number(&self, features: &NameFeatures, format: &str) -> Option<u32> {
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
                        && p.style == style
                        && family
                            .as_ref()
                            .is_none_or(|f| logical_name_from_parsed(p).eq_ignore_ascii_case(f))
                });
                let value = found.next()?.number;
                found.all(|p| p.number == value).then_some(value)
            }
            Self::Token {
                ordinal,
                left,
                right,
            } => {
                let n = features
                    .numbers
                    .iter()
                    .filter(|n| !(format == "7z" && n.seven_zip_literal))
                    .nth(*ordinal)?;
                (n.left == *left && n.right == *right && n.value > 0).then_some(n.value)
            }
        }
    }

    pub fn tokens<'a>(
        features: &'a NameFeatures,
        format: &'a str,
    ) -> impl Iterator<Item = Self> + 'a {
        features
            .numbers
            .iter()
            .filter(move |n| !(format == "7z" && n.seven_zip_literal))
            .enumerate()
            .map(|(ordinal, n)| Self::Token {
                ordinal,
                left: n.left.clone(),
                right: n.right.clone(),
            })
    }
}

pub(super) fn logical_name(name: &str, features: &NameFeatures, format: &str) -> String {
    features
        .family(format)
        .unwrap_or_else(|| first_dot_stem(name).to_ascii_lowercase())
}
