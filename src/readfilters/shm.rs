//! Shared-memory per-IP byte buckets, backing [`ReadBandwidth`](super::ReadBandwidth).
//!
//! ## Why
//!
//! strfry constructs its `PluginReadPolicy` as a **per-thread local**, lazily
//! spawning one `./noteguard read` child process per read-serving thread
//! (`reqWorker` + `reqMonitor`). With N such threads an IP's connections — spread
//! across processes by reconnects (dispatch is `connId % numThreads`) — hit N
//! independent in-memory buckets, so the effective per-IP budget is
//! `bytes_per_minute × N`. To enforce ONE authoritative budget per IP while
//! keeping N parallel processes, all `noteguard read` processes on a host share a
//! single [`ByteBucket`]-table through one `mmap`'d `MAP_SHARED` file.
//!
//! ## Layout (a `repr(C)` header + a fixed open-addressing slot table)
//!
//! ```text
//! Header @0 : magic u64 | version u32 | slot_count u32 | init_state AtomicU32 | pad
//! Slot[i]   : lock AtomicU32 | state u32 | key_len u32 | pad | key [u8; KEY_LEN]
//!                            | tokens u64 (f64 bits) | last_refill u64 (monotonic ns)
//! ```
//!
//! The table is keyed by the client IP text (or a `conn:<id>` fallback), hashed
//! with a **fixed** FNV-1a — never the std `RandomState`, whose per-process seed
//! would send the same IP to different slots in different processes and defeat
//! the whole point. Slots are found by linear probing from the hashed home slot.
//!
//! ## Concurrency
//!
//! Each slot carries its own spinlock (`AtomicU32`, `Acquire`/`Release`). All of
//! a slot's body — `tokens`, `last_refill`, `key`, `state` — is read and written
//! only while that lock is held; the lock's acquire/release fences publish those
//! plain (non-atomic) accesses across processes, the standard shared-memory-IPC
//! pattern (sound on one host + one architecture with coherent caches). Because
//! the empty-slot check happens *while holding the slot's lock*, two processes
//! inserting the same key serialize on the first-empty slot and cannot
//! double-insert; and since entries are **never evicted**, probe chains never
//! break, so a key's insertion slot is deterministic.
//!
//! ## Fail-open
//!
//! Matching the [`ReadFilter`](crate::ReadFilter) contract, every operation
//! returns `None` (→ the caller delivers) rather than block or withhold when it
//! cannot proceed: a slot lock it cannot acquire within a bound, a full table, an
//! over-long key, or (at construction) a failed `mmap`/init. A throttle that
//! breaks must never silence a subscriber's own authorized feed.
//!
//! ## Lifetime / staleness
//!
//! The default path lives on `tmpfs` (`/dev/shm`), so the table survives strfry
//! *restarts* (the buckets, and `CLOCK_MONOTONIC`, persist across a plugin
//! process dying and respawning — the "reconcile on restart" property, for free)
//! but is cleared on *reboot*. As belt-and-suspenders for a non-tmpfs path
//! carried across a reboot (where `CLOCK_MONOTONIC` resets and a stored
//! `last_refill` would sit in the future), [`SlotGuard::refill`] treats a
//! future timestamp as fully stale and resets the slot to a full bucket.

use memmap2::{MmapMut, MmapOptions};
use std::fs::OpenOptions;
use std::io;
use std::ptr::{addr_of, addr_of_mut};
use std::sync::atomic::{AtomicU32, Ordering};

/// File magic: `"NGRDBW"` + version bytes, little-endian. Bumped with `VERSION`
/// when the on-disk layout changes so an attaching process rejects a stale file.
const MAGIC: u64 = u64::from_le_bytes(*b"NGRDBW\x00\x01");
/// On-disk layout version. Attaching to a file with a different version fails
/// (→ fail open), rather than misinterpreting its bytes.
const VERSION: u32 = 1;

/// Fixed key capacity: an IPv6 textual address is at most 45 bytes
/// (`INET6_ADDRSTRLEN`-ish), and the `conn:<id>` fallback is at most ~25, so 48
/// covers every key. A longer key fails open.
const KEY_LEN: usize = 48;

// Slot `state`.
const EMPTY: u32 = 0;
const OCCUPIED: u32 = 1;

// Header `init_state` — the one-time init handshake.
const UNINIT: u32 = 0;
const INITIALIZING: u32 = 1;
const READY: u32 = 2;

/// Bounded spins before a slot-lock acquire gives up and fails open. Critical
/// sections are a few memory ops (nanoseconds), so this only ever trips on a
/// process that died holding the lock — in which case failing open is correct.
const SPIN_LIMIT: u32 = 100_000;
/// Bounded spins waiting for another process to finish one-time init.
const INIT_SPIN_LIMIT: u64 = 10_000_000;

/// One minute in nanoseconds — the refill window (and the clamp on elapsed time).
const MINUTE_NS: u64 = 60 * 1_000_000_000;

/// Shared header. `repr(C)` so every process agrees on the layout.
#[repr(C)]
struct Header {
    magic: u64,
    version: u32,
    slot_count: u32,
    init_state: AtomicU32,
    _pad: u32,
}

/// One bucket slot. `repr(C, align(8))` so `tokens`/`last_refill` are naturally
/// aligned and the array packs deterministically across processes.
#[repr(C, align(8))]
struct Slot {
    /// Per-slot spinlock: 0 = free, 1 = held. First field, so its address is the
    /// slot's address.
    lock: AtomicU32,
    /// `EMPTY` or `OCCUPIED`. Written under `lock`.
    state: u32,
    /// Bytes of `key` in use. Written under `lock`.
    key_len: u32,
    _pad: u32,
    /// The client IP text (or `conn:<id>` fallback). Written once under `lock`,
    /// immutable thereafter (no eviction).
    key: [u8; KEY_LEN],
    /// Bucket balance in bytes, stored as `f64::to_bits`. Under `lock`.
    tokens: u64,
    /// Last refill, `CLOCK_MONOTONIC` nanoseconds. Under `lock`.
    last_refill: u64,
}

const HEADER_SIZE: usize = std::mem::size_of::<Header>();
const SLOT_SIZE: usize = std::mem::size_of::<Slot>();

/// System-wide monotonic time in nanoseconds. `CLOCK_MONOTONIC` is boot-relative
/// on Linux and so comparable across every process on the host — unlike
/// [`std::time::Instant`], which is process-relative and cannot live in shared
/// memory.
fn monotonic_ns() -> u64 {
    // SAFETY: `clock_gettime` fills the provided `timespec`; CLOCK_MONOTONIC is
    // always available on Linux.
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe {
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
    }
    (ts.tv_sec as u64)
        .wrapping_mul(1_000_000_000)
        .wrapping_add(ts.tv_nsec as u64)
}

/// FNV-1a (64-bit). A *fixed* hash — deterministic across processes, unlike the
/// std hasher's per-process-seeded `RandomState`, which would place the same IP
/// in different slots in different processes and re-shard the buckets.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn slot_count_for(max_ips: u32) -> usize {
    // Power of two so the home slot is a cheap mask. At least one slot.
    (max_ips.max(1) as usize).next_power_of_two()
}

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// A held slot lock plus typed access to the slot body. Releases the lock on
/// drop. All body access goes through this guard, so it only happens under the
/// lock.
struct SlotGuard {
    slot: *mut Slot,
}

impl SlotGuard {
    /// Try to take a slot's lock within [`SPIN_LIMIT`]. `None` (→ fail open) if it
    /// stays held — only a crashed lock-holder makes that happen in practice.
    fn lock(slot: *mut Slot) -> Option<SlotGuard> {
        // The lock is the slot's first field, so the slot pointer is the lock's.
        let lock = unsafe { &*(slot as *const AtomicU32) };
        for _ in 0..SPIN_LIMIT {
            if lock
                .compare_exchange_weak(0, 1, Ordering::Acquire, Ordering::Relaxed)
                .is_ok()
            {
                return Some(SlotGuard { slot });
            }
            std::hint::spin_loop();
        }
        None
    }

    fn state(&self) -> u32 {
        unsafe { addr_of!((*self.slot).state).read() }
    }
    fn set_state(&self, v: u32) {
        unsafe { addr_of_mut!((*self.slot).state).write(v) }
    }
    fn tokens(&self) -> f64 {
        f64::from_bits(unsafe { addr_of!((*self.slot).tokens).read() })
    }
    fn set_tokens(&self, v: f64) {
        unsafe { addr_of_mut!((*self.slot).tokens).write(v.to_bits()) }
    }
    fn last_refill(&self) -> u64 {
        unsafe { addr_of!((*self.slot).last_refill).read() }
    }
    fn set_last_refill(&self, v: u64) {
        unsafe { addr_of_mut!((*self.slot).last_refill).write(v) }
    }

    fn key_matches(&self, key: &[u8]) -> bool {
        unsafe {
            let len = addr_of!((*self.slot).key_len).read() as usize;
            if len != key.len() {
                return false;
            }
            let p = addr_of!((*self.slot).key) as *const u8;
            std::slice::from_raw_parts(p, len) == key
        }
    }

    /// Claim an empty slot for `key` with a full bucket. Caller must hold the
    /// slot lock (i.e. be this guard) and have checked the slot is `EMPTY`.
    fn claim(&self, key: &[u8], cap: f64) {
        unsafe {
            let p = addr_of_mut!((*self.slot).key) as *mut u8;
            std::ptr::copy_nonoverlapping(key.as_ptr(), p, key.len());
            addr_of_mut!((*self.slot).key_len).write(key.len() as u32);
        }
        self.set_tokens(cap);
        self.set_last_refill(monotonic_ns());
        self.set_state(OCCUPIED);
    }

    /// Refill toward `cap` by the elapsed fraction of a minute (same shape as the
    /// write-side `ratelimit`), clamped to one minute and capped at `cap`. A
    /// `last_refill` in the future (a stale entry carried across a reboot, where
    /// the monotonic clock reset) resets the slot to full.
    fn refill(&self, cap: f64) {
        let now = monotonic_ns();
        let last = self.last_refill();
        if last > now {
            // Stale from a prior boot: reset rather than freeze the bucket.
            self.set_tokens(cap);
            self.set_last_refill(now);
            return;
        }
        let elapsed = (now - last).min(MINUTE_NS);
        let refill = (elapsed as f64 / MINUTE_NS as f64) * cap;
        self.set_tokens((self.tokens() + refill).min(cap));
        self.set_last_refill(now);
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let lock = unsafe { &*(self.slot as *const AtomicU32) };
        lock.store(0, Ordering::Release);
    }
}

/// A fixed-size open-addressing table of per-IP byte buckets over one `mmap`.
///
/// Cloned only conceptually — construct one per process ([`Self::open`] to share
/// a file across processes, [`Self::anonymous`] for a private per-process map).
pub struct SharedByteBuckets {
    // Keeps the mapping alive; the raw `base`/pointers below borrow from it. The
    // mapping's virtual address is stable across a move of this struct.
    _mmap: MmapMut,
    base: *mut u8,
    slot_count: usize,
}

impl SharedByteBuckets {
    /// Attach to (creating + initializing if absent) the shared file at `path`,
    /// sized for `max_ips` distinct IPs (rounded up to a power of two). Every
    /// `noteguard read` process on the host passes the same path + `max_ips`.
    pub fn open(path: &str, max_ips: u32) -> io::Result<Self> {
        let slot_count = slot_count_for(max_ips);
        let total = HEADER_SIZE + slot_count * SLOT_SIZE;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            // Never truncate: attaching to an existing table must preserve it
            // (grow-only sizing below), which is how the buckets survive a restart.
            .truncate(false)
            .open(path)?;
        // Grow-only: the first process sizes a fresh (zero-length) file; a process
        // attaching to an existing one leaves it be (and validates via the header).
        if (file.metadata()?.len() as usize) < total {
            file.set_len(total as u64)?;
        }
        // SAFETY: the file is sized to at least `total`; the mapping is `MAP_SHARED`.
        let mmap = unsafe { MmapOptions::new().len(total).map_mut(&file)? };
        Self::from_mmap(mmap, slot_count)
    }

    /// A private, per-process map (zero-filled anonymous mapping). Used when no
    /// shared path is configured, and in tests. Behaves exactly like the old
    /// per-process `HashMap`, through the same slot logic.
    pub fn anonymous(max_ips: u32) -> io::Result<Self> {
        let slot_count = slot_count_for(max_ips);
        let total = HEADER_SIZE + slot_count * SLOT_SIZE;
        let mmap = MmapMut::map_anon(total)?;
        Self::from_mmap(mmap, slot_count)
    }

    fn from_mmap(mmap: MmapMut, slot_count: usize) -> io::Result<Self> {
        let base = mmap.as_ptr() as *mut u8;
        let this = SharedByteBuckets {
            _mmap: mmap,
            base,
            slot_count,
        };
        this.init_or_attach(slot_count)?;
        Ok(this)
    }

    /// One-time init handshake: the first process to see `UNINIT` writes the
    /// header and flips to `READY`; concurrent creators spin until `READY`; a
    /// process attaching to an already-`READY` file validates magic/version and
    /// that its `max_ips` agrees (a mismatch fails, → fail open, rather than
    /// silently sharding against a different-sized table). A freshly created file
    /// (or anon mapping) is zero-filled, so its slots are already `EMPTY`.
    fn init_or_attach(&self, our_slot_count: usize) -> io::Result<()> {
        let hdr = self.base as *mut Header;
        let state = unsafe { &*addr_of!((*hdr).init_state) };
        let mut spins = 0u64;
        loop {
            match state.compare_exchange(
                UNINIT,
                INITIALIZING,
                Ordering::Acquire,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    unsafe {
                        addr_of_mut!((*hdr).magic).write(MAGIC);
                        addr_of_mut!((*hdr).version).write(VERSION);
                        addr_of_mut!((*hdr).slot_count).write(our_slot_count as u32);
                    }
                    // Slots are already zeroed (fresh ftruncate / anon map) => EMPTY.
                    state.store(READY, Ordering::Release);
                    return Ok(());
                }
                Err(INITIALIZING) => {
                    spins += 1;
                    if spins > INIT_SPIN_LIMIT {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "shared byte-bucket init stalled (crashed initializer?)",
                        ));
                    }
                    std::hint::spin_loop();
                }
                Err(READY) => {
                    let (magic, version, sc) = unsafe {
                        (
                            addr_of!((*hdr).magic).read(),
                            addr_of!((*hdr).version).read(),
                            addr_of!((*hdr).slot_count).read(),
                        )
                    };
                    if magic != MAGIC {
                        return Err(invalid("shared byte-bucket file has wrong magic"));
                    }
                    if version != VERSION {
                        return Err(invalid("shared byte-bucket file version mismatch"));
                    }
                    if sc as usize != our_slot_count {
                        return Err(invalid(
                            "shared byte-bucket max_ips disagrees with the existing file",
                        ));
                    }
                    return Ok(());
                }
                Err(_) => return Err(invalid("shared byte-bucket init_state corrupt")),
            }
        }
    }

    pub fn slot_count(&self) -> usize {
        self.slot_count
    }

    fn slot_ptr(&self, i: usize) -> *mut Slot {
        // Slots begin right after the header; `base` is page-aligned so the
        // 8-aligned header + slots stay naturally aligned.
        unsafe { (self.base.add(HEADER_SIZE) as *mut Slot).add(i) }
    }

    /// Find `key`'s slot (or insert it, full), returning its held lock guard.
    /// `None` (→ fail open) if the key is over-long, a probed slot's lock cannot
    /// be taken, or the table is full.
    fn acquire(&self, key: &[u8], cap: f64) -> Option<SlotGuard> {
        if key.is_empty() || key.len() > KEY_LEN {
            return None;
        }
        let mask = self.slot_count - 1;
        let home = (fnv1a(key) as usize) & mask;
        for step in 0..self.slot_count {
            let idx = (home + step) & mask;
            let guard = SlotGuard::lock(self.slot_ptr(idx))?;
            match guard.state() {
                EMPTY => {
                    // First empty in the probe chain: claim it. The empty-check
                    // is under the lock, so a racing insert of the same key waits
                    // here and then matches instead of double-inserting.
                    guard.claim(key, cap);
                    return Some(guard);
                }
                _ if guard.key_matches(key) => return Some(guard),
                // Occupied by a different key: release and probe on.
                _ => drop(guard),
            }
        }
        // Table full: no matching or empty slot within a full sweep.
        None
    }

    /// Refill `key`'s bucket and return its current balance in bytes. Creates the
    /// bucket full on first sight. `None` → fail open.
    pub fn tokens_after_refill(&self, key: &[u8], cap: f64) -> Option<f64> {
        let guard = self.acquire(key, cap)?;
        guard.refill(cap);
        Some(guard.tokens())
    }

    /// Refill `key`'s bucket and subtract `amount` bytes (may go transiently
    /// negative; it recovers on the next refill). Best-effort: a fail-open
    /// `acquire` just skips the charge.
    pub fn spend(&self, key: &[u8], cap: f64, amount: f64) {
        if let Some(guard) = self.acquire(key, cap) {
            guard.refill(cap);
            guard.set_tokens(guard.tokens() - amount);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32 as TestCtr;

    /// A unique temp path with best-effort cleanup on drop.
    struct TmpFile(String);
    impl TmpFile {
        fn new(tag: &str) -> TmpFile {
            static CTR: TestCtr = TestCtr::new(0);
            let n = CTR.fetch_add(1, Ordering::Relaxed);
            let p = std::env::temp_dir()
                .join(format!("ng-shm-{}-{}-{}", tag, std::process::id(), n))
                .to_string_lossy()
                .into_owned();
            let _ = std::fs::remove_file(&p);
            TmpFile(p)
        }
    }
    impl Drop for TmpFile {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// Find `n` distinct keys that all hash to the same home slot in a table of
    /// `slot_count`, to force probing/collisions deterministically.
    fn colliding_keys(slot_count: usize, n: usize) -> Vec<Vec<u8>> {
        let mask = slot_count - 1;
        let target = 0usize;
        let mut out = Vec::new();
        let mut i = 0u64;
        while out.len() < n {
            let k = format!("collide-{}", i).into_bytes();
            if (fnv1a(&k) as usize) & mask == target {
                out.push(k);
            }
            i += 1;
        }
        out
    }

    #[test]
    fn anonymous_creates_full_bucket_and_spends() {
        let m = SharedByteBuckets::anonymous(16).unwrap();
        let cap = 1000.0;
        // First sight: a full bucket.
        assert_eq!(m.tokens_after_refill(b"1.2.3.4", cap), Some(cap));
        m.spend(b"1.2.3.4", cap, 600.0);
        let t = m.tokens_after_refill(b"1.2.3.4", cap).unwrap();
        assert!((t - 400.0).abs() < 1.0, "expected ~400, got {t}");
    }

    #[test]
    fn spend_can_go_transiently_negative() {
        let m = SharedByteBuckets::anonymous(16).unwrap();
        let cap = 100.0;
        m.tokens_after_refill(b"9.9.9.9", cap);
        m.spend(b"9.9.9.9", cap, 250.0);
        let t = m.tokens_after_refill(b"9.9.9.9", cap).unwrap();
        assert!(t < 0.0, "overspend should leave a negative balance, got {t}");
    }

    #[test]
    fn refill_recovers_over_elapsed_time() {
        let m = SharedByteBuckets::anonymous(16).unwrap();
        let cap = 6000.0;
        m.tokens_after_refill(b"5.5.5.5", cap);
        // Drain, then backdate last_refill by 30s: half a minute => half a cap.
        {
            let g = m.acquire(b"5.5.5.5", cap).unwrap();
            g.set_tokens(0.0);
            g.set_last_refill(monotonic_ns() - 30 * 1_000_000_000);
        }
        let t = m.tokens_after_refill(b"5.5.5.5", cap).unwrap();
        assert!(
            (t - cap / 2.0).abs() < cap * 0.02,
            "expected ~half cap ({}), got {t}",
            cap / 2.0
        );
    }

    #[test]
    fn refill_clamps_at_one_minute() {
        let m = SharedByteBuckets::anonymous(16).unwrap();
        let cap = 1000.0;
        m.tokens_after_refill(b"1.1.1.1", cap);
        {
            let g = m.acquire(b"1.1.1.1", cap).unwrap();
            g.set_tokens(0.0);
            // A long time ago: refill is clamped to one minute => full, not more.
            g.set_last_refill(monotonic_ns() - 600 * 1_000_000_000);
        }
        assert_eq!(m.tokens_after_refill(b"1.1.1.1", cap), Some(cap));
    }

    #[test]
    fn future_timestamp_resets_slot() {
        let m = SharedByteBuckets::anonymous(16).unwrap();
        let cap = 1000.0;
        m.tokens_after_refill(b"2.2.2.2", cap);
        {
            let g = m.acquire(b"2.2.2.2", cap).unwrap();
            g.set_tokens(0.0);
            // Stale-from-prior-boot: a last_refill in the future resets to full.
            g.set_last_refill(monotonic_ns() + 100 * 1_000_000_000);
        }
        assert_eq!(m.tokens_after_refill(b"2.2.2.2", cap), Some(cap));
    }

    #[test]
    fn probing_keeps_colliding_keys_distinct() {
        // A 4-slot table; three keys sharing a home slot must land in distinct
        // slots (linear probing) and keep independent balances.
        let m = SharedByteBuckets::anonymous(4).unwrap();
        assert_eq!(m.slot_count(), 4);
        let cap = 1000.0;
        let keys = colliding_keys(4, 3);
        for k in &keys {
            m.tokens_after_refill(k, cap);
        }
        m.spend(&keys[0], cap, 100.0);
        m.spend(&keys[1], cap, 200.0);
        // keys[2] untouched, keys[0]/[1] independently charged.
        assert!((m.tokens_after_refill(&keys[0], cap).unwrap() - 900.0).abs() < 1.0);
        assert!((m.tokens_after_refill(&keys[1], cap).unwrap() - 800.0).abs() < 1.0);
        assert!((m.tokens_after_refill(&keys[2], cap).unwrap() - 1000.0).abs() < 1.0);
    }

    #[test]
    fn full_table_fails_open() {
        // Two slots, three distinct keys: the third has nowhere to go => None
        // (fail open), never clobbering an existing bucket.
        let m = SharedByteBuckets::anonymous(2).unwrap();
        assert_eq!(m.slot_count(), 2);
        let cap = 1000.0;
        assert!(m.tokens_after_refill(b"a", cap).is_some());
        assert!(m.tokens_after_refill(b"b", cap).is_some());
        assert_eq!(m.tokens_after_refill(b"c", cap), None);
        // A key already present still resolves even when the table is full.
        assert!(m.tokens_after_refill(b"a", cap).is_some());
    }

    #[test]
    fn overlong_key_fails_open() {
        let m = SharedByteBuckets::anonymous(16).unwrap();
        let long = vec![b'x'; KEY_LEN + 1];
        assert_eq!(m.tokens_after_refill(&long, 1000.0), None);
        m.spend(&long, 1000.0, 10.0); // no-op, must not panic
    }

    #[test]
    fn two_views_over_one_file_share_state() {
        // The crux: two SharedByteBuckets over ONE file model two processes.
        // A spend through view A is visible through view B — the whole point.
        let tf = TmpFile::new("share");
        let a = SharedByteBuckets::open(&tf.0, 64).unwrap();
        let b = SharedByteBuckets::open(&tf.0, 64).unwrap(); // attaches to A's file
        let cap = 1000.0;
        a.tokens_after_refill(b"1.2.3.4", cap); // A creates a full bucket
        a.spend(b"1.2.3.4", cap, 700.0); // A: 300 left
        let seen_by_b = b.tokens_after_refill(b"1.2.3.4", cap).unwrap();
        assert!(
            (seen_by_b - 300.0).abs() < 1.0,
            "view B must see view A's spend; got {seen_by_b}"
        );
        // And a spend through B is visible through A.
        b.spend(b"1.2.3.4", cap, 100.0);
        let seen_by_a = a.tokens_after_refill(b"1.2.3.4", cap).unwrap();
        assert!((seen_by_a - 200.0).abs() < 1.0, "got {seen_by_a}");
    }

    #[test]
    fn reopen_reuses_existing_buckets() {
        // Survive-restart: drop the map and reopen the same file; the bucket's
        // balance persists (as it would across a strfry restart on tmpfs).
        let tf = TmpFile::new("reopen");
        let cap = 1000.0;
        {
            let a = SharedByteBuckets::open(&tf.0, 64).unwrap();
            a.tokens_after_refill(b"7.7.7.7", cap);
            a.spend(b"7.7.7.7", cap, 400.0);
        }
        let b = SharedByteBuckets::open(&tf.0, 64).unwrap();
        let t = b.tokens_after_refill(b"7.7.7.7", cap).unwrap();
        assert!((t - 600.0).abs() < 1.0, "expected persisted ~600, got {t}");
    }

    #[test]
    fn attach_with_mismatched_capacity_fails() {
        let tf = TmpFile::new("mismatch");
        let _a = SharedByteBuckets::open(&tf.0, 64).unwrap();
        // A second process configured for a different max_ips must not silently
        // shard against a different-sized table.
        assert!(SharedByteBuckets::open(&tf.0, 128).is_err());
    }
}
