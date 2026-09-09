# noteguard

A high performance note filter plugin system for [strfry]

WIP!

## Usage

Filters are registered and loaded from the [noteguard.toml](noteguard.toml) config.

You can add any new filter you want by implementing the `NoteFilter` trait and registering it with noteguard via the `register_filter` method.

The `pipeline` config specifies the order in which filters are run. When the first `reject` or `shadowReject` action is hit, then the pipeline stops and returns the rejection error.

```toml
pipeline = ["protected_events", "kinds", "whitelist", "ratelimit", "forwarder"]

[filters.ratelimit]
posts_per_minute = 8
whitelist = ["127.0.0.1"]
message = "rate-limit: you note too much"

[filters.whitelist]
pubkeys = ["16c21558762108afc34e4ff19e4ed51d9a48f79e0c34531efc423d21ab435e93"]
ips = ["127.0.0.1"]

[filters.kinds]
kinds = [30065, 1064]

[filters.kinds.messages]
30065 = "blocked: files on nostr is dumb"
1064 = "blocked: files on nostr is dumb"

[filters.protected_events]

[filters.forwarder]
relay = "ws://localhost:8080"
queue_size = 2000
```

## Installation

You can install noteguard by copying the binary to the strfry directory.

Static musl builds are convenient ways to package noteguard for deployment. It enables you to copy the binary directly to your server, ensure that you are using the correct architecture that your server is running.

You most likely want `x86_64-unknown-linux-musl` or `aarch64-unknown-linux-musl`. Install this target with rustup, build noteguard, and copy the binary to the server:

```sh
$ rustup target add x86_64-unknown-linux-musl
$ cargo build --target x86_64-unknown-linux-musl --release
$ scp ./target/x86_64-unknown-linux-musl/release/noteguard server:strfry
$ scp noteguard.toml server:strfry
```

Test that the binary executes by running it on the server:

```sh
$ cd strfry
$ <<<'{}' ./noteguard
Failed to parse input: missing field `type` at line 1 column 2
```

Configure `noteguard.toml` with your preferred filters.

Now you can then setup your `strfry.conf` to use the noteguard by adding it as a writePolicy plugin:

```
writePolicy {
    # If non-empty, path to an executable script that implements the writePolicy plugin logic
    plugin = "./noteguard"
}
```

And you're done! Enjoy.

## Filters

You can use any of the builtin filters, or create your own!

This is the initial release, and only includes one filter so far:

### Ratelimit

* name: `ratelimit`

The ratelimit filter limits the rate at which notes are written to the relay per-ip.

Settings:

- `notes_per_minute`: the number of notes per minute which are allowed to be written per ip.

- `whitelist` *optional*: a list of IP4 or IP6 addresses that are allowed to bypass the ratelimit.

- `message` *optional*: the error message to return when connection is rate-limited. default is: `rate-limited: you are noting too much`

### Whitelist

* name: `whitelist`

The whitelist filter only allows notes to pass if it matches a particular pubkey or source ip:

- `pubkeys` *optional*: a list of hex public keys to let through

- `ips` *optional*: a list of ip addresses to let through

Either criteria can match

### Blacklist

* name: `blacklist`

The blacklist filter blocks notes that match any pubkey, ip, or CIDR range:

- `pubkeys` *optional*: a list of hex public keys to block

- `ips` *optional*: a list of IP addresses to block

- `cidrs` *optional*: a list of CIDR ranges to block

### Kinds

* name: `kinds`

A filter that blacklists certain kinds

- `kinds`: a list of kind integers to block

- `kinds.messages` *optional*: a map of kinds to message to deliver when the kind is blocked

Example:

```toml
[filters.kinds]
kinds = [30065, 1064]

[filters.kinds.messages]
30065 = "blocked: files on nostr is dumb"
1064 = "blocked: files on nostr is dumb"
```

### Protected Events

See [nip70]

* name: `protected_events`

There are no config options, but an empty config entry is still needed:

`[filters.protected_events]`

### Forwarder

* name: `forwarder`

You need to compile with the `forwarder` feature to enable this filter:

```sh
$ cargo build --features forwarder --release
```

The forwarder filter allows you to forward notes to another relay. Notes will
be queued if the connection goes down (up to the `queue_size` buffer limit)

- `relay` - the relay to forward notes to, eg: `ws://localhost:8080`

- `queue_size` *optional* - size of the note queue, this is used to buffer notes if the connection goes down. Default is 1000.

### NScript (experimental)

* name: `nscript`

Runs a user-supplied **WASM** module as a note filter. Instead of compiling
filters into noteguard, the logic lives in a sandboxed wasm guest that reads the
note through an *accessor ABI* — a set of imported host functions
(`note_pubkey`, `note_kind`, `note_targets_owner`, `is_following`, …) — rather
than parsing a note buffer itself. The note's byte format is therefore an
implementation detail of the host, and guests stay tiny (the example below is
under 300 bytes: no note parser is linked into it).

The intent is programmable, per-npub server-side filtering (e.g. inbox / mention
spam control), eventually submitted to the relay as a signed event. This is a
**Phase 0 spike**: the guest is loaded from a local path and the owner context
comes from config.

Build with the `nscript` feature:

```sh
$ cargo build --features nscript
```

Config:

- `module` — path to the compiled guest `.wasm`
- `owner` *optional* — hex pubkey the script is scoped to (its "inbox owner")
- `follows` *optional* — hex pubkeys the owner follows (backs `is_following`)
- `message` *optional* — message returned to the client on reject

```toml
[filters.nscript]
module = "./follows_only.wasm"
owner = "1111…1111"
follows = ["2222…2222"]
message = "blocked: not in owner's follows"
```

Guests are bounded by wasm **fuel** and a **memory cap** per note, and noteguard
**fails open** (accepts) if a guest traps or exhausts its budget, so a broken or
runaway filter can't block writes or hang the relay.

An example guest (`follows-only`, an inbox filter that rejects notes to the owner
from non-followed authors) lives in [`nscript-guests/`](nscript-guests). Build it
with:

```sh
$ cd nscript-guests/follows-only
$ cargo build --release --target wasm32-unknown-unknown
```

## Read-policy (readPolicy) mode

Everything above is the **write-side** plugin: it decides what gets *stored* (a
reject deletes the event for everyone). strfry also has a **read-side**
(`readPolicy`) plugin hook that decides, *per subscription*, which already-stored
events are *delivered* to that particular subscriber — the right hook for
personal/inbox feed filtering and per-connection read throttling. Withholding an
event never touches storage and never affects any other subscriber.

Run noteguard in read mode with the `read` subcommand and point strfry's
`relay.readPolicy.plugin` at it:

```
readPolicy {
    plugin = "./noteguard read"
}
```

The subscription's subscriber (the NIP-42 `authed` pubkey) and client IP are
cached at `reqOpen` and handed to every filter, so a filter can scope its
decisions to whoever is reading. Like strfry itself, the read loop **fails
open**: a filter that errors, an unparseable message, or a misconfigured
pipeline entry delivers rather than withholds.

Like the write side, the read side is a **composable filter pipeline**: it reads
a `[readpolicy]` table from the same config file as the write side
(`noteguard.toml`, or the file named by `$NOTEGUARD_CONFIG`) with an ordered
`pipeline` of read-filter names plus a per-filter `[readpolicy.filters.X]`
config table — the read-side analogue of the write-side `pipeline` /
`[filters.X]`. An empty (or absent) pipeline delivers everything (every
subscription is passthrough). Filters run in order per event.

```toml
[readpolicy]
# compose the read filters, in order. Empty/absent => deliver all.
pipeline = ["max_events_per_conn", "read_bandwidth", "nscript"]

# connection-level throttle: max events delivered per connection.
[readpolicy.filters.max_events_per_conn]
max = 5000

# read-bandwidth throttle: max BYTES of events delivered per minute, keyed per
# client IP. Reconnecting with a fresh connId from the same IP does NOT reset the
# budget — the read-side analogue of the write-side `ratelimit` filter, metering
# the exact wire size of each delivered event via an Instant token bucket
# (tokens = bytes). Once an IP's per-minute byte budget is spent, further events
# in the batch are withheld.
[readpolicy.filters.read_bandwidth]
bytes_per_minute = 5000000
# exempt entries: an entry matches a connection's client IP OR its authed pubkey
# hex (optional). A whitelisted connection is never metered and takes the
# passthrough fast path.
whitelist = ["127.0.0.1", "0000…0000"]

# guest wasm applied to subscriptions (owner = the authed subscriber). Requires
# the `nscript` build feature; the pipeline entry is skipped (fail open) in a
# build without it.
[readpolicy.filters.nscript]
module = "./mute_word.wasm"
# STUB for follow-set distribution: owner-hex -> hex pubkeys they follow.
# Backs the guest's is_following accessor until scripts/follows are sourced
# from signed on-relay submissions.
[readpolicy.filters.nscript.follows]
# "1111…1111" = ["2222…2222"]
```

Each filter is a [`ReadFilter`](src/read_filter.rs) — a lifecycle-aware,
stateful analogue of the write-side [`NoteFilter`](src/note_filter.rs). It can
allocate per-subscription / per-connection state at `reqOpen` and free it at
`reqClose`/`connClose`, and returns one of **deliver**, **skip** (withhold this
event), or **stop** (withhold this event and the rest of the batch) per event —
so the throttles can bound a batch once a budget runs out. Adding a new read
behavior is now a matter of implementing the trait and registering it, exactly
like the write side.

**Passthrough fast path:** a subscription for which *no* filter needs per-event
work answers `reqOpen` with `{"action":"accept","passthrough":true}`. strfry then
skips all per-event marshaling for that subscription and delivers it via its
zero-copy fast path, never sending `req` batches (it still sends
`reqClose`/`connClose`). Each filter declares whether it needs events for a given
subscription, and the engine ANDs those: an empty pipeline is always
passthrough; a configured throttle keeps the subscription non-passthrough
(strfry must keep sending events for the counter/byte-meter to bound delivery);
a bandwidth-whitelisted connection is passthrough (it is never metered); and a
`nscript` filter is non-passthrough only when it actually loaded a guest.
Emitting the field is forward-compatible: a strfry without passthrough support
simply ignores it.

**Per-IP bandwidth keying needs the client IP:** `read_bandwidth` meters per
client IP so a reconnect can't reset the budget. `req` batches carry
no IP, so noteguard caches the IP from the `reqOpen` message (added by newer
strfry builds, alongside `connId`/`authed`) under its `connId`. Against an older
strfry that doesn't send `ip`, metering degrades gracefully to per-connection
(logged once per connection as a warning) — a reconnect then gets a fresh budget.

**Per-thread scoping (important):** strfry runs *one plugin process per
read-serving thread* (`relay.numThreads.reqWorker` / `reqMonitor`), each with its
own in-memory byte buckets. A given connection is served by one thread, so the
per-IP budget only survives a reconnect that lands on the *same* thread; the
effective per-IP budget is therefore up to `numThreads ×
read_bandwidth.bytes_per_minute`. This is the same per-process scoping the write-side
`ratelimit` filter has (its buckets live in the per-ingester-thread process).
For exact per-IP enforcement, set `relay.numThreads.reqWorker = 1` and
`relay.numThreads.reqMonitor = 1`; otherwise treat the limit as approximate.
(True cross-thread enforcement would require sharing bucket state across plugin
processes, which this phase does not do.)

### NScript read filter (experimental)

* name: `nscript`

The read path can drive the same nscript WASM runtime as the write-side
[`nscript`](#nscript-experimental) filter, so it needs the `nscript` feature
(`cargo build --release --features nscript`); without it the pipeline entry is
logged and skipped (fail open). The subscriber (the NIP-42 `authed` pubkey) is
the script **owner**, so a per-npub feed filter runs scoped to whoever is
reading. The guest is compiled once per process and re-scoped per subscriber —
no recompile per subscription. The `Verdict` collapses on the read path to
**deliver** (`Accept`) vs **withhold** (anything else); there is no "shadow"
concept for reads. It fails open: a missing/failed module or a trapping guest
delivers everything.

An unauthenticated subscription (no `authed`) still runs the guest, but with no
owner: an owner-scoped filter like `follows-only` then no-ops and delivers
everything, while an owner-independent filter still applies. The
[`mute-word`](nscript-guests/mute-word) example guest (withholds kind-1 notes
containing a muted word) is owner-independent, which makes it convenient for
exercising the read path without AUTH:

```sh
$ cd nscript-guests/mute-word
$ cargo build --release --target wasm32-unknown-unknown
```

Script/follow **distribution is stubbed** for this phase (configured statically
via `module` and the `follows` map rather than sourced from signed submission
events on the relay); the point of the read mode today is the protocol + runtime
wiring.


## Testing

You can test your filters like so:

```sh
$ cargo build
$ <test/inputs ./target/debug/noteguard
$ ./test/delayed | ./target/debug/noteguard
```

[strfry]: https://github.com/hoytech/strfry
[nip70]: https://github.com/nostr-protocol/nips/blob/protected-events-tag/70.md
