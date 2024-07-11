
# noteguard

A high performance note filter plugin system for [strfry]

WIP!

## Usage

Filters are registered and loaded from the [noteguard.toml](noteguard.toml) config.

You can add any new filter you want by implementing the `NoteFilter` trait and registering it with noteguard via the `register_filter` method.

The `pipeline` config specifies the order in which filters are run. When the first `reject` or `shadowReject` action is hit, then the pipeline stops and returns the rejection error.

```toml
pipeline = ["protected_events", "kinds", "whitelist", "ratelimit"]

[filters.ratelimit]
posts_per_minute = 8
whitelist = ["127.0.0.1"]

[filters.whitelist]
pubkeys = ["16c21558762108afc34e4ff19e4ed51d9a48f79e0c34531efc423d21ab435e93"]
ips = ["127.0.0.1"]

[filters.kinds]
kinds = [30065, 1064]

[filters.kinds.messages]
30065 = "blocked: files on nostr is dumb"
1064 = "blocked: files on nostr is dumb"

[filters.protected_events]
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

### Whitelist

* name: `whitelist`

The whitelist filter only allows notes to pass if it matches a particular pubkey or source ip:

- `pubkeys` *optional*: a list of hex public keys to let through

- `ips` *optional*: a list of ip addresses to let through

Either criteria can match

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

## Testing

You can test your filters like so:

```sh
$ cargo build
$ <test/inputs ./target/debug/noteguard
$ ./test/delay | ./target/debug/noteguard
```

[strfry]: https://github.com/hoytech/strfry
[nip70]: https://github.com/nostr-protocol/nips/blob/protected-events-tag/70.md
