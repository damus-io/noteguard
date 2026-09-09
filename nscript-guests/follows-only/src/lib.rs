//! Example nscript guest: a follows-only inbox filter.
//!
//! Rejects notes addressed (p-tagged) to the scoped owner unless the author is
//! someone the owner follows. Notes that don't target the owner are accepted
//! untouched.
//!
//! Note how there is no note parser compiled into this module: it reads the note
//! purely through the host accessor ABI. Owner-relative context (who the owner
//! is, and their follow set) lives on the host, so this module is reusable logic
//! independent of any particular npub.

#![no_std]

use core::panic::PanicInfo;

// ---- accessor ABI (imported from the host) ----
#[link(wasm_import_module = "env")]
extern "C" {
    /// Writes the 32-byte author pubkey into `out_ptr`; returns bytes written.
    fn note_pubkey(out_ptr: *mut u8) -> i32;
    /// 1 if the note p-tags the scoped owner, else 0.
    fn note_targets_owner() -> i32;
    /// 1 if the 32-byte pubkey at `pk_ptr` is in the owner's follow set.
    fn is_following(pk_ptr: *const u8) -> i32;
}

const ACCEPT: i32 = 0;
const REJECT: i32 = 1;

/// The host calls this once per note; the current note is implicit.
#[no_mangle]
pub extern "C" fn filter_note() -> i32 {
    unsafe {
        // Only govern notes addressed to our owner; leave everything else alone.
        if note_targets_owner() == 0 {
            return ACCEPT;
        }

        let mut author = [0u8; 32];
        note_pubkey(author.as_mut_ptr());

        if is_following(author.as_ptr()) == 1 {
            ACCEPT
        } else {
            REJECT
        }
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
    loop {}
}
