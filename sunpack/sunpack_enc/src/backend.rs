//! ENC's custom cipher ISA policy. Detect once per process; bind once per key.
//! No keys, executor, scratch buffers or experiment switches live here.
use std::sync::OnceLock;

// SAFETY: the selected function may enter target_feature code. Callers bind it
// only through the target baseline/detected capabilities; bindings are immutable.
pub(super) type Encrypt<C> = unsafe fn(&C, &mut [u8]);

#[derive(Default)]
pub(super) struct Capabilities {
    #[cfg(target_arch = "x86_64")]
    pub(super) avx2: bool,
    #[cfg(target_arch = "x86_64")]
    shani: bool,
    #[cfg(target_arch = "aarch64")]
    sha2: bool,
}

pub(super) fn capabilities() -> &'static Capabilities {
    static DETECTED: OnceLock<Capabilities> = OnceLock::new();
    DETECTED.get_or_init(|| Capabilities {
        #[cfg(target_arch = "x86_64")]
        avx2: std::arch::is_x86_feature_detected!("avx2"),
        #[cfg(target_arch = "x86_64")]
        shani: std::arch::is_x86_feature_detected!("sha")
            && std::arch::is_x86_feature_detected!("ssse3")
            && std::arch::is_x86_feature_detected!("sse4.1"),
        #[cfg(target_arch = "aarch64")]
        sha2: std::arch::is_aarch64_feature_detected!("sha2"),
    })
}

impl Capabilities {
    #[cfg(target_arch = "x86_64")]
    pub(super) fn vector<C>(&self, scalar: Encrypt<C>, accelerated: Encrypt<C>) -> Encrypt<C> {
        if self.avx2 {
            accelerated
        } else {
            scalar
        }
    }

    pub(super) fn sha<C>(
        &self,
        portable: Encrypt<C>,
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))] accelerated: Encrypt<C>,
    ) -> Encrypt<C> {
        #[cfg(target_arch = "x86_64")]
        if self.shani {
            return accelerated;
        }
        #[cfg(target_arch = "aarch64")]
        if self.sha2 {
            return accelerated;
        }
        portable
    }
}

#[cfg(all(test, target_arch = "aarch64"))]
mod arm_tests {
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
}

#[cfg(all(test, target_arch = "x86_64"))]
mod tests {
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
}
