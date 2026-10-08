//! Argon2id SIMD primitives on SunPack's existing shared Rayon executor.
//! No helper threads, spin barrier, additional pool or retained scratch cache.
use argon2_rust::__internal::FillSegmentFn;
use argon2_rust::{
    Algorithm, Error, Params, Version,
    __internal::{
        backend, fill_first_blocks, fill_segment_fn, finalize, initial_hash, Block, Instance,
        Position,
    },
};
use rayon::prelude::*;
use zeroize::Zeroizing;

struct LaneExecutor<'a> {
    instance: &'a Instance,
    fill: FillSegmentFn,
}
// SAFETY: this wrapper only exposes one fill per lane in a given slice. Each
// lane writes its own segment and reads only segments allowed by Argon2's
// indexing rules. Rayon joins all lanes before the next slice starts. The
// borrowed, initialized and 64-byte-aligned arena outlives every scoped task;
// no Rust reference into its blocks is accessed until all fills return.
unsafe impl Sync for LaneExecutor<'_> {}
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
    threads: usize,
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
    let threads = if threads > 1 {
        threads
            .min(instance.lanes as usize)
            .min(rayon::current_num_threads())
    } else {
        1
    };
    let executor = LaneExecutor {
        instance: &instance,
        fill,
    };
    for pass in 0..instance.passes {
        for slice in 0..4 {
            if threads == 1 {
                for lane in 0..instance.lanes {
                    executor.fill_lane(pass, slice, lane);
                }
            } else {
                // Exactly one task per granted credit. A task may fill
                // several lanes; all join before the next Argon2 slice.
                (0..threads)
                    .into_par_iter()
                    .with_max_len(1)
                    .for_each(|task| {
                        for lane in (task as u32..instance.lanes).step_by(threads) {
                            executor.fill_lane(pass, slice, lane);
                        }
                    });
            }
        }
    }
    finalize(&instance, output)
}
