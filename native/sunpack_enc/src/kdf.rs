//! Argon2id SIMD primitives on SunPack's existing shared Rayon executor.
//! No helper threads, spin barrier, additional pool or retained scratch cache.
#[cfg(feature = "parallel-kdf")]
use argon2_rust::__internal::FillSegmentFn;
use argon2_rust::{
    Algorithm, Error, Params, Version,
    __internal::{
        backend, fill_first_blocks, fill_segment_fn, finalize, initial_hash, Block, Instance,
        Position,
    },
};
use zeroize::Zeroizing;

#[cfg(feature = "parallel-kdf")]
struct LaneExecutor<'a> {
    instance: &'a Instance,
    fill: FillSegmentFn,
}
// SAFETY: this wrapper only exposes one fill per lane in a given slice. Each
// lane writes its own segment and reads only segments allowed by Argon2's
// indexing rules. Rayon joins all lanes before the next slice starts. The
// borrowed, initialized and 64-byte-aligned arena outlives every scoped task;
// no Rust reference into its blocks is accessed until all fills return.
#[cfg(feature = "parallel-kdf")]
unsafe impl Sync for LaneExecutor<'_> {}
#[cfg(feature = "parallel-kdf")]
impl LaneExecutor<'_> {
    fn fill_lane(&self, pass: u32, slice: u32, lane: u32) {
        // SAFETY: unique (lane, slice), bounded position, valid arena. `fill`
        // came from runtime CPU detection before any tasks were scheduled.
        unsafe { (self.fill)(self.instance, Position::new(pass, lane, slice, 0)) };
    }
}

pub(super) fn derive(
    params: &Params,
    master: &[u8; 256],
    salt: &[u8; 32],
    output: &mut [u8; 256],
    memory: &mut [Block],
) -> Result<(), Error> {
    if memory.len() != params.memory_blocks() as usize || params.tag_len_bytes() != output.len() {
        return Err(Error::IncorrectParameter);
    }
    let mut initial = Zeroizing::new(initial_hash(
        Algorithm::Argon2id,
        Version::V0x13,
        params,
        master,
        salt,
        &[],
        &[],
    )?);
    let (_, _, lane_length) = params.memory_layout();
    fill_first_blocks(&mut initial, memory, params.lanes(), lane_length)?;
    // SAFETY: Vec<Block>/the supplied Block slice is initialized and aligned to
    // 64 bytes; its exact size was checked above. All uses finish inside this
    // call, before the exclusive memory borrow returns to the caller.
    let instance = unsafe {
        Instance::new(
            memory.as_mut_ptr(),
            memory.len(),
            Algorithm::Argon2id,
            Version::V0x13,
            params,
        )
    };
    let fill = fill_segment_fn(backend());
    #[cfg(feature = "parallel-kdf")]
    {
        use rayon::prelude::*;
        let executor = LaneExecutor {
            instance: &instance,
            fill,
        };
        for pass in 0..instance.passes {
            for slice in 0..4 {
                (0..instance.lanes)
                    .into_par_iter()
                    .for_each(|lane| executor.fill_lane(pass, slice, lane));
            }
        }
    }
    #[cfg(not(feature = "parallel-kdf"))]
    for pass in 0..instance.passes {
        for slice in 0..4 {
            for lane in 0..instance.lanes {
                // SAFETY: this CPU supports the detected backend; valid arena,
                // bounded position and one writer, with every slice completed.
                unsafe { fill(&instance, Position::new(pass, lane, slice, 0)) };
            }
        }
    }
    finalize(&instance, output)
}
