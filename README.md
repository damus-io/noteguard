
# noteguard

A high performance note filter plugin system for [strfry]

WIP!

## Usage

Filters are registered and loaded from the [noteguard.toml](noteguard.toml) config.

You can add any new filter you want by implementing the `NoteFilter` trait and registering it with noteguard via the `register_filter` method.

The `pipeline` config specifies the order in which filters are run. When the first `reject` or `shadowReject` action is hit, then the pipeline stops and returns the rejection error.

```toml
pipeline = ["whitelist", "ratelimit"]

[filters.ratelimit]
posts_per_minute = 8
whitelist = ["127.0.0.1"]

[filters.whitelist]
#pubkeys = ["32e1827635450ebb3c5a7d12c1f8e7b2b514439ac10a67eef3d9fd9c5c68e245"]
ips = ["127.0.0.1", "127.0.0.2"]
```

## Filters

You can use any of the builtin filters, or create your own!

This is the initial release, and only includes one filter so far:

### Ratelimit

The ratelimit filter limits the rate at which notes are written to the relay per-ip.

Settings:

- `notes_per_minute`: the number of notes per minute which are allowed to be written per ip.

- `whitelist`: a list of IP4 or IP6 addresses that are allowed to bypass the ratelimit.

## Whitelist

The whitelist filter only allows notes to pass if it matches a particular pubkey or source ip:

- `pubkeys`: a list of hex public keys to let through

- `ips`: a list of ip addresses to let through

Either criteria can match

## Testing

You can test your filters like so:

```sh
$ cargo build --release
$ ./target/release/noteguard
$ <test/test-inputs ./target/release/noteguard
```

[strfry]: https://github.com/hoytech/strfry
