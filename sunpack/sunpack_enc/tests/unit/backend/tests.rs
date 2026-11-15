use super::*;
#[test]
fn avx2_and_sha_capabilities_are_independent() {
    // These callbacks contain no ISA instructions, so all four policies can
    // be exercised without pretending this CPU supports a missing ISA.
    fn portable(_: &(), bytes: &mut [u8]) {
        bytes[0] = 0;
    }
    fn accelerated(_: &(), bytes: &mut [u8]) {
        bytes[0] = 1;
    }
    for avx2 in [false, true] {
        for shani in [false, true] {
            let caps = Capabilities { avx2, shani };
            let mut bytes = [2];
            unsafe {
                caps.vector(portable, accelerated)(&(), &mut bytes);
            }
            assert_eq!(bytes[0], u8::from(avx2));
            unsafe {
                caps.sha(portable, accelerated)(&(), &mut bytes);
            }
            assert_eq!(bytes[0], u8::from(shani));
        }
    }
}
