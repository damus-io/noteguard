//! Example nscript guest: an owner-independent muted-word read filter.
//!
//! Withholds kind-1 notes whose content contains the muted word "spam";
//! everything else is delivered. Unlike `follows-only`, this guest reads no
//! owner context, so it applies identically to every subscriber (authenticated
//! or not) — which makes it convenient for exercising the read-side
//! deliver/withhold path without NIP-42 AUTH.
//!
//! As with the other guests, there is no note parser compiled in: the content
//! is read through the host accessor ABI.

#![no_std]

use core::panic::PanicInfo;

#[link(wasm_import_module = "env")]
extern "C" {
    /// The note's kind.
    fn note_kind() -> i64;
    /// Copies up to `cap` bytes of the note content into `out_ptr`; returns the
    /// content's true length (which may exceed `cap`).
    fn note_content(out_ptr: *mut u8, cap: i32) -> i32;
}

const ACCEPT: i32 = 0;
const REJECT: i32 = 1;

/// The muted word. A note delivering it is withheld.
const MUTED: &[u8] = b"spam";

/// Scratch buffer for the note content. Content longer than this is truncated
/// for the scan (a muted word past the cutoff won't match — acceptable for a
/// spike; a real filter would stream or raise the cap).
const CAP: usize = 4096;

#[no_mangle]
pub extern "C" fn filter_note() -> i32 {
    unsafe {
        // Only govern kind-1 (text notes); leave everything else alone.
        if note_kind() != 1 {
            return ACCEPT;
        }

        let mut buf = [0u8; CAP];
        let true_len = note_content(buf.as_mut_ptr(), CAP as i32);
        let n = if true_len < 0 {
            0
        } else {
            (true_len as usize).min(CAP)
        };

        if contains(&buf[..n], MUTED) {
            REJECT
        } else {
            ACCEPT
        }
    }
}

/// Naive substring search (no_std, no allocator).
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return needle.is_empty();
    }
    let mut i = 0;
    while i + needle.len() <= haystack.len() {
        if &haystack[i..i + needle.len()] == needle {
            return true;
        }
        i += 1;
    }
    false
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
