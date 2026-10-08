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
    pub(super) fn vector<C>(
        &self,
        _scalar: Encrypt<C>,
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))] accelerated: Encrypt<C>,
    ) -> Encrypt<C> {
        #[cfg(target_arch = "x86_64")]
        if self.avx2 {
            return accelerated;
        }
        #[cfg(target_arch = "aarch64")]
        // aarch64-pc-windows-msvc has +v8a,+neon as its target baseline.
        // Short blocks and tails still use each cipher's scalar implementation.
        let selected = accelerated;
        #[cfg(not(target_arch = "aarch64"))]
        let selected = _scalar;
        selected
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
pub(super) mod arm_tests {
    use super::*;

    #[test]
    fn neon_baseline_and_optional_sha2_are_independent() {
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
                caps.vector(portable, accelerated)(&(), &mut bytes);
            }
            assert_eq!(bytes[0], 1);
            unsafe {
                caps.sha(portable, accelerated)(&(), &mut bytes);
            }
            assert_eq!(bytes[0], u8::from(sha2));
        }
        println!("ARM64 baseline=neon sha2={}", capabilities().sha2);
    }

    // Manual diagnostic only: no timing assertions on shared CI hardware.
    // Key expansion/allocation are outside timing. Rotate measurement order and
    // report medians; padded SIMD is explicitly labelled for short-block cost.
    pub(in super::super) fn crossover<C>(
        name: &str,
        cipher: &C,
        block_size: usize,
        lanes: usize,
        counts: &[usize],
        scalar: Encrypt<C>,
        accelerated: Encrypt<C>,
        dispatch: Encrypt<C>,
    ) {
        use std::{hint::black_box, time::Instant};
        const ITERATIONS: usize = 20_000;
        println!("cipher,blocks,scalar_ns,accelerated_padded_ns,dispatch_ns");
        for &blocks in counts {
            let size = blocks * block_size;
            let padded = blocks.div_ceil(lanes) * lanes * block_size;
            let mut bytes = vec![0x73; padded];
            let mut samples = [[0u128; 7]; 3];
            for round in 0..7 {
                for index in 0..3 {
                    let mode = (round + index) % 3;
                    let (encrypt, len) =
                        [(scalar, size), (accelerated, padded), (dispatch, size)][mode];
                    for _ in 0..100 {
                        unsafe {
                            encrypt(black_box(cipher), black_box(&mut bytes[..len]));
                        }
                    }
                    let start = Instant::now();
                    for _ in 0..ITERATIONS {
                        unsafe {
                            encrypt(black_box(cipher), black_box(&mut bytes[..len]));
                        }
                    }
                    samples[mode][round] = start.elapsed().as_nanos();
                    black_box(&bytes);
                }
            }
            let medians = samples.map(|mut values| {
                values.sort_unstable();
                values[3] as f64 / ITERATIONS as f64
            });
            println!(
                "{name},{blocks},{:.2},{:.2},{:.2}",
                medians[0], medians[1], medians[2]
            );
        }
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
