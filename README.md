
# noteguard

A high performance note filter plugin system for [strfry]

WIP!

## Usage

Filters are registered and loaded from the [noteguard.toml](noteguard.toml) config.

You can add any new filter you want by implementing the `NoteFilter` trait and registering it with noteguard via the `register_filter` method.

The `pipeline` config specifies the order in which filters are run. When the first `reject` or `shadowReject` action is hit, then the pipeline stops and returns the rejection error.

```toml

pipeline = ["ratelimit"]

[filters.ratelimit]
notes_per_second = 1
whitelist = ["127.0.0.1"]
```

## Filters

You can use any of the builtin filters, or create your own!

This is the initial release, and only includes one filter so far:

### Ratelimit

The ratelimit filter limits the rate at which notes are written to the relay per-ip.

Settings:

- `notes_per_second`: the delay in seconds between accepted notes. 1 means only one note can be written per second. 2 means only 1 note can be written every 2 seconds, etc. TODO: rename this because its confusing.

- `whitelist`: a list of IP4 or IP6 addresses that are allowed to bypass the ratelimit.

[strfry]: https://github.com/hoytech/strfry
