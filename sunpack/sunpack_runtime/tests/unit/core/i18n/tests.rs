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
