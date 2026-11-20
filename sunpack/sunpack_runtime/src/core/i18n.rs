mod catalog;

#[repr(u8)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Language {
    #[default]
    En,
    Zh,
    ZhTw,
    Ja,
    Ko,
}

impl Language {
    const ALL: [Self; 5] = [Self::En, Self::Zh, Self::ZhTw, Self::Ja, Self::Ko];
    const CODES: [&str; Self::ALL.len()] = ["en", "zh", "zh-TW", "ja", "ko"];

    pub fn parse(value: &str) -> Self {
        let value = value.trim();
        Self::CODES.iter().position(|code| code.eq_ignore_ascii_case(value))
            .map_or(Self::En, |index| Self::ALL[index])
    }

    pub(crate) fn from_index(index: u8) -> Self {
        Self::ALL[usize::from(index)]
    }

    pub fn lookup(self, key: &str) -> Option<&'static str> {
        let index = catalog::MESSAGES.binary_search_by_key(&key, |message| message.0).ok()?;
        Some(catalog::MESSAGES[index].1[self as usize])
    }

    pub fn text(self, key: &str) -> &str {
        self.lookup(key).unwrap_or(key)
    }

    pub fn translate(self, key: &str, params: &[(&str, &str)]) -> String {
        let mut text = self.text(key);
        let mut result = String::with_capacity(text.len());
        while let Some((prefix, after)) = text.split_once('{') {
            result.push_str(prefix);
            let Some((name, rest)) = after.split_once('}') else {
                result.push('{');
                result.push_str(after);
                return result;
            };
            if let Some((_, value)) = params.iter().find(|(param, _)| *param == name) {
                result.push_str(value);
            } else {
                result.push('{');
                result.push_str(name);
                result.push('}');
            }
            text = rest;
        }
        result.push_str(text);
        result
    }
}

#[cfg(test)]
#[path = "../../tests/unit/core/i18n/tests.rs"]
mod tests;
