//! Adversarial nscript guest: never returns. Must be stopped by host fuel.
#![no_std]
use core::panic::PanicInfo;

#[no_mangle]
pub extern "C" fn filter_note() -> i32 {
    let mut x: u64 = 0;
    loop {
        // volatile-ish spin so the optimizer can't fold it away
        x = x.wrapping_add(1);
        unsafe { core::ptr::read_volatile(&x); }
    }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! { loop {} }
