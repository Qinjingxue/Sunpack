use super::*;

#[test]
fn ascii_password_bytes_are_borrowed_unchanged() {
    let encoded = zip_password_bytes("secret-123");
    assert!(matches!(encoded, Cow::Borrowed(_)));
    assert_eq!(&*encoded, b"secret-123");
}

#[cfg(windows)]
#[test]
fn non_ascii_password_uses_the_ansi_codepage_like_7zip() {
    extern "system" {
        fn GetACP() -> u32;
    }
    let encoded = zip_password_bytes("密码");
    match unsafe { GetACP() } {
        936 => assert_eq!(&*encoded, &[0xC3, 0xDC, 0xC2, 0xEB]),
        65001 => assert_eq!(&*encoded, "密码".as_bytes()),
        _ => assert_ne!(&*encoded, "密码".as_bytes()),
    }
}
