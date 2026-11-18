use super::*;

// Independent coverage: every AES strength's non-first PBKDF2 block and
// long/UTF-8 HMAC keys against full PBKDF2, beyond archive success checks.
// This small oracle matrix catches block/offset errors without archive IO.
#[test]
fn selective_verifier_matches_full_pbkdf2_for_all_strengths() {
    for password in ["", "password", "⑨密码", &"long-key".repeat(16)] {
        for (key_len, salt_len) in [(16, 8), (24, 12), (32, 16)] {
            let salt = vec![0xa5; salt_len];
            let mut full = vec![0u8; key_len * 2 + 2];
            pbkdf2::pbkdf2_hmac::<Sha1>(password.as_bytes(), &salt, 1000, &mut full);
            let verifier = &full[key_len * 2..];
            assert_eq!(winzip_aes_verifier(password.as_bytes(), &salt, key_len).unwrap(), verifier);
        }
    }
}
