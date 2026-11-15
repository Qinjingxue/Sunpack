mod catalog;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Language {
    #[default]
    En,
    Zh,
}

impl Language {
    pub fn parse(value: &str) -> Self {
        if value.trim().eq_ignore_ascii_case("zh") {
            Self::Zh
        } else {
            Self::En
        }
    }

    pub fn lookup(self, key: &str) -> Option<&'static str> {
        catalog::MESSAGES.binary_search_by_key(&key, |message| message.0).ok().map(|index| {
            let (_, en, zh) = catalog::MESSAGES[index];
            match self { Self::En => en, Self::Zh => zh }
        })
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
mod tests {
    use super::*;

    #[test]
    fn every_catalog_key_is_sorted_and_resolves_in_both_languages() {
        assert!(catalog::MESSAGES.windows(2).all(|pair| pair[0].0 < pair[1].0));
        for &(key, en, zh) in catalog::MESSAGES {
            assert_eq!(Language::En.lookup(key), Some(en), "{key}");
            assert_eq!(Language::Zh.lookup(key), Some(zh), "{key}");
        }
        assert_eq!(Language::En.text("cli.press_enter"), "Press Enter to continue...");
        assert_eq!(Language::Zh.text("cli.press_enter"), "按回车键继续...");
    }
}
