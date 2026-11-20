use super::*;

#[test]
fn translations_resolve_in_all_languages_and_preserve_placeholders() {
    let pattern = regex::Regex::new(r"\{[a-zA-Z_]+\}").unwrap();
    fn placeholders<'a>(pattern: &regex::Regex, template: &'a str) -> Vec<&'a str> {
        let mut names: Vec<_> = pattern.find_iter(template).map(|entry| entry.as_str()).collect();
        names.sort_unstable();
        names
    }
    for (language, code) in Language::ALL.into_iter().zip(Language::CODES) {
        assert_eq!(Language::parse(&format!(" {} ", code.to_ascii_uppercase())), language);
        assert_eq!(Language::from_index(language as u8), language);
        for &(key, messages) in catalog::MESSAGES {
            let message = messages[language as usize];
            assert!(!message.is_empty(), "{key} ({code})");
            assert_eq!(language.lookup(key), Some(message), "{key} ({code})");
            assert_eq!(placeholders(&pattern, message), placeholders(&pattern, messages[0]), "{key} ({code})");
        }
    }
    assert_eq!(Language::parse("unknown"), Language::En);
}
