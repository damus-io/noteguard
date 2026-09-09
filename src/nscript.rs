//! Phase 0 spike of the nscript wasm filter runtime.
//!
//! The ABI is an *accessor interface* over an opaque note handle: the guest
//! never parses a note buffer, it calls imported `note_*` host functions to read
//! fields. The note's byte format is therefore an implementation detail — today
//! we back the accessors with the serde [`Note`]; later this becomes an
//! `ndb_note` (with an optional `note_raw` zero-copy fast path). Owner-relative
//! context (which npub the script is scoped to, and their follows) lives on the
//! host, so guests stay reusable, owner-agnostic logic.

use crate::Note;
use std::collections::HashSet;
use wasmtime::{
    AsContext, AsContextMut, Caller, Config, Engine, Extern, Linker, Memory, Module, Store,
    StoreLimits, StoreLimitsBuilder,
};

/// Guest action codes returned from `filter_note`.
const ACT_REJECT: i32 = 1;
const ACT_SHADOW_REJECT: i32 = 2;

/// CPU budget (wasm fuel units) per note. Bounds runaway guests deterministically.
const DEFAULT_FUEL: u64 = 50_000_000;

/// Max guest linear memory (bytes).
const MAX_MEMORY: usize = 16 * 1024 * 1024;

/// The verdict a guest returns for a note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Reject,
    ShadowReject,
}

/// Per-invocation host state exposed to the accessor functions.
struct HostState {
    note: Note,
    owner: Option<[u8; 32]>,
    follows: HashSet<[u8; 32]>,
    limits: StoreLimits,
}

/// A compiled nscript module plus the owner context it runs under.
pub struct Runtime {
    engine: Engine,
    module: Module,
    linker: Linker<HostState>,
    owner: Option<[u8; 32]>,
    follows: HashSet<[u8; 32]>,
    fuel: u64,
}

impl Runtime {
    /// Compile the guest at `path` and wire up the accessor ABI.
    ///
    /// `owner` is the hex pubkey the script is scoped to and `follows` are hex
    /// pubkeys that owner follows (backing for `note_targets_owner` and
    /// `is_following`).
    pub fn load(path: &str, owner: &Option<String>, follows: &[String]) -> Result<Self, String> {
        let mut config = Config::new();
        config.consume_fuel(true);
        let engine = Engine::new(&config).map_err(|e| e.to_string())?;
        let module = Module::from_file(&engine, path).map_err(|e| e.to_string())?;

        let mut linker = Linker::new(&engine);
        register_host_functions(&mut linker).map_err(|e| e.to_string())?;

        let owner = owner.as_deref().and_then(hex32);
        let follows = follows.iter().filter_map(|h| hex32(h)).collect();

        Ok(Runtime {
            engine,
            module,
            linker,
            owner,
            follows,
            fuel: DEFAULT_FUEL,
        })
    }

    /// Re-scope this already-compiled guest to a different owner, without
    /// recompiling. `engine`, `module` and `linker` are owner-independent and
    /// internally reference-counted, so cloning them is cheap — a per-subscriber
    /// runtime costs no JIT compile or file read.
    pub fn rescope(&self, owner: &Option<String>, follows: &[String]) -> Self {
        Runtime {
            engine: self.engine.clone(),
            module: self.module.clone(),
            linker: self.linker.clone(),
            owner: owner.as_deref().and_then(hex32),
            follows: follows.iter().filter_map(|h| hex32(h)).collect(),
            fuel: self.fuel,
        }
    }

    /// Run the guest filter against `note`, returning its verdict.
    ///
    /// A fresh [`Store`] is created per note (the compiled module is reused), so
    /// guests get no state between invocations. Fuel and a memory cap bound the
    /// resources a single call may consume.
    pub fn run(&self, note: &Note) -> Result<Verdict, String> {
        let state = HostState {
            note: note.clone(),
            owner: self.owner,
            follows: self.follows.clone(),
            limits: StoreLimitsBuilder::new().memory_size(MAX_MEMORY).build(),
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|s| &mut s.limits);
        store.set_fuel(self.fuel).map_err(|e| e.to_string())?;

        let instance = self
            .linker
            .instantiate(&mut store, &self.module)
            .map_err(|e| e.to_string())?;
        let func = instance
            .get_typed_func::<(), i32>(&mut store, "filter_note")
            .map_err(|e| e.to_string())?;
        let code = func.call(&mut store, ()).map_err(|e| e.to_string())?;

        Ok(match code {
            ACT_REJECT => Verdict::Reject,
            ACT_SHADOW_REJECT => Verdict::ShadowReject,
            _ => Verdict::Accept,
        })
    }
}

/// Register the accessor ABI on the linker under the `env` module.
///
/// Low-level accessors (`note_pubkey`, `note_id`, `note_kind`, `note_created_at`,
/// `note_content`) expose raw note fields; higher-level owner-relative
/// capabilities (`note_targets_owner`, `is_following`) keep owner context on the
/// host. Variable-length reads use the `(out_ptr, cap) -> true_len` convention.
fn register_host_functions(linker: &mut Linker<HostState>) -> Result<(), wasmtime::Error> {
    // note_pubkey(out_ptr) -> 32 : raw author pubkey bytes (0 on error)
    linker.func_wrap(
        "env",
        "note_pubkey",
        |mut caller: Caller<'_, HostState>, out: i32| -> i32 {
            let pk = match hex32(&caller.data().note.pubkey) {
                Some(p) => p,
                None => return 0,
            };
            write_bytes(&mut caller, out, &pk)
        },
    )?;

    // note_id(out_ptr) -> 32 : raw event id bytes (0 on error)
    linker.func_wrap(
        "env",
        "note_id",
        |mut caller: Caller<'_, HostState>, out: i32| -> i32 {
            let id = match hex32(&caller.data().note.id) {
                Some(p) => p,
                None => return 0,
            };
            write_bytes(&mut caller, out, &id)
        },
    )?;

    // note_kind() -> kind
    linker.func_wrap("env", "note_kind", |caller: Caller<'_, HostState>| -> i64 {
        caller.data().note.kind
    })?;

    // note_created_at() -> unix seconds
    linker.func_wrap(
        "env",
        "note_created_at",
        |caller: Caller<'_, HostState>| -> i64 { caller.data().note.created_at },
    )?;

    // note_content(out_ptr, cap) -> true_len : utf8 content, truncated to cap
    linker.func_wrap(
        "env",
        "note_content",
        |mut caller: Caller<'_, HostState>, out: i32, cap: i32| -> i32 {
            let content = caller.data().note.content.clone();
            let bytes = content.as_bytes();
            let n = bytes.len().min(cap.max(0) as usize);
            write_bytes(&mut caller, out, &bytes[..n]);
            bytes.len() as i32
        },
    )?;

    // note_targets_owner() -> bool : does the note p-tag the scoped owner?
    linker.func_wrap(
        "env",
        "note_targets_owner",
        |caller: Caller<'_, HostState>| -> i32 {
            let owner = match caller.data().owner {
                Some(o) => o,
                None => return 0,
            };
            let hit =
                caller.data().note.tags.iter().any(|t| {
                    t.len() >= 2 && t[0] == "p" && hex32(&t[1]).map_or(false, |p| p == owner)
                });
            hit as i32
        },
    )?;

    // is_following(pk_ptr) -> bool : is this 32-byte pubkey in the owner's follows?
    linker.func_wrap(
        "env",
        "is_following",
        |mut caller: Caller<'_, HostState>, pk_ptr: i32| -> i32 {
            let target = match read_array::<32>(&mut caller, pk_ptr) {
                Some(b) => b,
                None => return 0,
            };
            caller.data().follows.contains(&target) as i32
        },
    )?;

    // log(ptr, len) : debug logging from the guest
    linker.func_wrap(
        "env",
        "log",
        |mut caller: Caller<'_, HostState>, ptr: i32, len: i32| {
            if let Some(s) = read_str(&mut caller, ptr, len) {
                log::info!("nscript: {}", s);
            }
        },
    )?;

    Ok(())
}

/// Resolve the guest's exported linear memory.
fn memory(caller: &mut Caller<'_, HostState>) -> Option<Memory> {
    match caller.get_export("memory") {
        Some(Extern::Memory(m)) => Some(m),
        _ => None,
    }
}

/// Write `data` into guest memory at `ptr`, returning the number of bytes
/// written (0 on failure).
fn write_bytes(caller: &mut Caller<'_, HostState>, ptr: i32, data: &[u8]) -> i32 {
    let mem = match memory(caller) {
        Some(m) => m,
        None => return 0,
    };
    match mem.write(caller.as_context_mut(), ptr as usize, data) {
        Ok(()) => data.len() as i32,
        Err(_) => 0,
    }
}

/// Read a fixed-size array from guest memory at `ptr`.
fn read_array<const N: usize>(caller: &mut Caller<'_, HostState>, ptr: i32) -> Option<[u8; N]> {
    let mem = memory(caller)?;
    let mut buf = [0u8; N];
    mem.read(caller.as_context(), ptr as usize, &mut buf).ok()?;
    Some(buf)
}

/// Read a utf8 string of `len` bytes from guest memory at `ptr`.
fn read_str(caller: &mut Caller<'_, HostState>, ptr: i32, len: i32) -> Option<String> {
    let mem = memory(caller)?;
    let mut buf = vec![0u8; len.max(0) as usize];
    mem.read(caller.as_context(), ptr as usize, &mut buf).ok()?;
    String::from_utf8(buf).ok()
}

/// Decode a single hex nibble.
fn hex_val(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Decode a 64-char hex string into a 32-byte array.
fn hex32(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = (hex_val(b[2 * i])? << 4) | hex_val(b[2 * i + 1])?;
    }
    Some(out)
}
