use super::*;

#[test]
fn translations_resolve_in_both_languages() {
    for &(key, en, zh) in catalog::MESSAGES {
        assert_eq!(Language::En.lookup(key), Some(en), "{key}");
        assert_eq!(Language::Zh.lookup(key), Some(zh), "{key}");
    }
}
