
# noteguard

A high performance note filter plugin system for [strfry]

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

[strfry]: https://github.com/hoytech/strfry
