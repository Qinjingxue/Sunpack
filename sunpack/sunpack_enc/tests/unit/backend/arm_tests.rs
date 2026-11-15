use super::*;

#[test]
fn optional_sha2_selects_hardware_or_portable() {
    fn portable(_: &(), bytes: &mut [u8]) {
        bytes[0] = 0;
    }
    fn accelerated(_: &(), bytes: &mut [u8]) {
        bytes[0] = 1;
    }
    for sha2 in [false, true] {
        let caps = Capabilities { sha2 };
        let mut bytes = [2];
        unsafe {
            caps.sha(portable, accelerated)(&(), &mut bytes);
        }
        assert_eq!(bytes[0], u8::from(sha2));
    }
    println!("ARM64 baseline=neon sha2={}", capabilities().sha2);
}
