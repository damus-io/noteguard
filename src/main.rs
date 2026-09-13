use noteguard::filters::{Blacklist, Content, Kinds, ProtectedEvents, RateLimit, Whitelist};

#[cfg(feature = "forwarder")]
use noteguard::filters::Forwarder;

#[cfg(feature = "nscript")]
use noteguard::filters::NScript;

use log::info;
use noteguard::{Action, InputMessage, NoteFilter, OutputMessage};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use std::collections::HashMap;
use std::io;

#[derive(Deserialize)]
struct Config {
    pipeline: Vec<String>,
    filters: HashMap<String, toml::Value>,

    /// Shared Cloudflare edge-ban config, consumed once at startup to arm the
    /// process-global banner every `BanTracker` escalates to. Ignored when the
    /// `cloudflare` feature is not built.
    #[cfg(feature = "cloudflare")]
    #[serde(default)]
    cloudflare: Option<noteguard::cloudflare::CloudflareConfig>,
}

type ConstructFilter = Box<fn(toml::Value) -> Result<Box<dyn NoteFilter>, toml::de::Error>>;

#[derive(Default)]
struct Noteguard {
    registered_filters: HashMap<String, ConstructFilter>,
    loaded_filters: Vec<Box<dyn NoteFilter>>,
}

impl Noteguard {
    pub fn new() -> Self {
        let mut noteguard = Noteguard::default();
        noteguard.register_builtin_filters();
        noteguard
    }

    pub fn register_filter<F: NoteFilter + 'static + Default + DeserializeOwned>(&mut self) {
        self.registered_filters.insert(
            F::name(&F::default()).to_string(),
            Box::new(|filter_config| {
                filter_config
                    .try_into()
                    .map(|filter: F| Box::new(filter) as Box<dyn NoteFilter>)
            }),
        );
    }

    /// All builtin filters are registered here, and are made available with
    /// every new instance of [`Noteguard`]
    fn register_builtin_filters(&mut self) {
        self.register_filter::<RateLimit>();
        self.register_filter::<Whitelist>();
        self.register_filter::<Blacklist>();
        self.register_filter::<ProtectedEvents>();
        self.register_filter::<Kinds>();
        self.register_filter::<Content>();

        #[cfg(feature = "forwarder")]
        self.register_filter::<Forwarder>();

        #[cfg(feature = "nscript")]
        self.register_filter::<NScript>();
    }

    /// Run the loaded filters. You must call `load_config` before calling this, otherwise
    /// not filters will be run.
    fn run(&mut self, input: InputMessage) -> OutputMessage {
        let mut mout: Option<OutputMessage> = None;

        let id = input.event.id.clone();
        for filter in &mut self.loaded_filters {
            let out = filter.filter_note(&input);
            match out.action {
                Action::Accept => {
                    mout = Some(out);
                    continue;
                }
                Action::Reject => {
                    return out;
                }
                Action::ShadowReject => {
                    return out;
                }
            }
        }

        mout.unwrap_or_else(|| OutputMessage::new(id, Action::Accept, None))
    }

    /// Initializes a noteguard config. If it finds any filter configurations
    /// matching the registered filters, it loads those into our filter pipeline.
    fn load_config(&mut self, config: &Config) -> Result<(), toml::de::Error> {
        self.loaded_filters.clear();

        for name in &config.pipeline {
            let config_value = config
                .filters
                .get(name)
                .unwrap_or_else(|| panic!("could not find filter configuration for {}", name));

            if let Some(constructor) = self.registered_filters.get(name.as_str()) {
                let filter = constructor(config_value.clone())?;
                self.loaded_filters.push(filter);
            } else {
                panic!("Found config settings with no matching filter: {}", name);
            }
        }

        Ok(())
    }
}

#[cfg(feature = "forwarder")]
#[tokio::main]
async fn main() {
    dispatch();
}

#[cfg(not(feature = "forwarder"))]
fn main() {
    dispatch();
}

/// Route to the write-policy loop (default) or the read-policy loop
/// (`noteguard read`). strfry invokes the read plugin as a plain shell command,
/// e.g. `relay.readPolicy.plugin = "./noteguard read"`.
fn dispatch() {
    env_logger::init();

    match std::env::args().nth(1).as_deref() {
        Some("read") => noteguard::readpolicy::run(),
        Some("dump-buckets") => dump_buckets(),
        _ => noteguard(),
    }
}

/// `noteguard dump-buckets [--json] [--capacity BYTES] [PATH]` — a read-only
/// operator peek into the shared per-IP read-bandwidth byte-bucket table (see
/// [`noteguard::readfilters::dump`]). Prints one row per OCCUPIED slot — the key
/// (client IP), bytes remaining, and how long ago the slot last refilled —
/// sorted most-throttled first. With `--capacity` it also shows each bucket
/// refilled to now and how full that leaves it. Never mutates the file.
fn dump_buckets() {
    use std::io::Write;

    // One minute in nanoseconds — the refill window, mirrored from the shm
    // module so `--capacity` can project a bucket's balance to now.
    const MINUTE_NS: f64 = 60.0 * 1_000_000_000.0;

    // Parse: an optional `--json`, an optional `--capacity BYTES`, and an
    // optional trailing PATH (defaults to the tmpfs file the read filter uses).
    let mut json = false;
    let mut capacity: Option<f64> = None;
    let mut path: Option<String> = None;
    let mut args = std::env::args().skip(2);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--json" => json = true,
            "--capacity" => {
                capacity = match args.next().and_then(|v| v.parse::<f64>().ok()) {
                    Some(c) if c > 0.0 => Some(c),
                    _ => {
                        eprintln!("dump-buckets: --capacity needs a positive number of bytes");
                        std::process::exit(2);
                    }
                };
            }
            "-h" | "--help" => {
                println!("usage: noteguard dump-buckets [--json] [--capacity BYTES] [PATH]");
                println!(
                    "  inspect the shared read-bandwidth byte buckets (default {})",
                    noteguard::readfilters::DEFAULT_PATH
                );
                return;
            }
            other if other.starts_with('-') => {
                eprintln!("dump-buckets: unknown flag {other}");
                std::process::exit(2);
            }
            other => {
                if path.replace(other.to_string()).is_some() {
                    eprintln!("dump-buckets: only one PATH may be given");
                    std::process::exit(2);
                }
            }
        }
    }
    let path = path.unwrap_or_else(|| noteguard::readfilters::DEFAULT_PATH.to_string());

    let dump = match noteguard::readfilters::dump(&path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("dump-buckets: cannot read {path}: {e}");
            std::process::exit(1);
        }
    };

    // Age in nanoseconds against the clock `dump` captured; negative means a
    // last_refill in the future (stale across a reboot — the monotonic clock
    // reset), which the read filter treats as fully stale (a full bucket).
    let age_ns =
        |e: &noteguard::readfilters::BucketEntry| dump.now_ns as i128 - e.last_refill_ns as i128;

    // Project a bucket's balance to now (same shape as the filter's refill:
    // elapsed/60 of a minute's capacity, clamped to a minute and capped; a
    // future timestamp resets to full). Only meaningful with a known capacity.
    let refilled = |e: &noteguard::readfilters::BucketEntry, cap: f64| -> f64 {
        let age = age_ns(e);
        if age < 0 {
            return cap;
        }
        let elapsed = (age as f64).min(MINUTE_NS);
        (e.tokens + (elapsed / MINUTE_NS) * cap).min(cap)
    };

    // Sort most-throttled first (fewest bytes remaining), the default an
    // operator hunting for a hammered IP wants at the top.
    let mut entries = dump.entries;
    entries.sort_by(|a, b| {
        a.tokens
            .partial_cmp(&b.tokens)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    if json {
        // Hand-roll the JSON so we don't need a Serialize impl on the shm types.
        let mut items = Vec::with_capacity(entries.len());
        for e in &entries {
            let mut obj = serde_json::json!({
                "key": e.key,
                "tokens": e.tokens,
                "last_refill_ns": e.last_refill_ns,
                "age_seconds": age_ns(e) as f64 / 1e9,
            });
            if let Some(cap) = capacity {
                let r = refilled(e, cap);
                obj["refilled_tokens"] = serde_json::json!(r);
                obj["percent_full"] = serde_json::json!(r / cap * 100.0);
            }
            items.push(obj);
        }
        let out = serde_json::json!({
            "path": path,
            "slot_count": dump.slot_count,
            "occupied": entries.len(),
            "now_ns": dump.now_ns,
            "capacity": capacity,
            "buckets": items,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&out).expect("dump JSON serializes")
        );
        return;
    }

    // Text output. Buffer to stdout so a huge table isn't line-flushed.
    let stdout = io::stdout();
    let mut out = io::BufWriter::new(stdout.lock());
    let _ = writeln!(
        out,
        "{}: slot_count={} occupied={}",
        path,
        dump.slot_count,
        entries.len()
    );
    if let Some(cap) = capacity {
        let _ = writeln!(
            out,
            "{:<46}  {:>16}  {:>10}  {:>16}  {:>7}",
            "KEY", "BYTES_REMAINING", "AGE", "REFILLED_NOW", "%FULL"
        );
        for e in &entries {
            let r = refilled(e, cap);
            let _ = writeln!(
                out,
                "{:<46}  {:>16.0}  {:>10}  {:>16.0}  {:>6.1}%",
                e.key,
                e.tokens,
                fmt_age(age_ns(e)),
                r,
                r / cap * 100.0,
            );
        }
    } else {
        let _ = writeln!(
            out,
            "{:<46}  {:>16}  {:>10}",
            "KEY", "BYTES_REMAINING", "AGE"
        );
        for e in &entries {
            let _ = writeln!(
                out,
                "{:<46}  {:>16.0}  {:>10}",
                e.key,
                e.tokens,
                fmt_age(age_ns(e)),
            );
        }
    }
}

/// Render a bucket age (nanoseconds; may be negative if stale across a reboot)
/// as a short human string like `4.2s` or `stale`.
fn fmt_age(age_ns: i128) -> String {
    if age_ns < 0 {
        return "stale".to_string();
    }
    let secs = age_ns as f64 / 1e9;
    if secs < 60.0 {
        format!("{secs:.1}s")
    } else {
        format!("{:.1}m", secs / 60.0)
    }
}

fn serialize_output_message(msg: &OutputMessage) -> String {
    serde_json::to_string(msg).expect("OutputMessage should always serialize correctly")
}

fn noteguard() {
    info!("running noteguard");

    let config_path = noteguard::config_path();
    let mut noteguard = Noteguard::new();

    let config: Config = {
        let contents = std::fs::read_to_string(&config_path).expect("Failed to read config file");
        toml::from_str(&contents).expect("Failed to parse config file")
    };

    noteguard
        .load_config(&config)
        .expect("Expected filter config to be loaded ok");

    // Arm the shared Cloudflare edge-banner before processing notes, so the very
    // first ban can escalate to the edge.
    #[cfg(feature = "cloudflare")]
    if let Some(cf) = config.cloudflare.clone() {
        noteguard::cloudflare::init(cf);
    }

    let stdin = io::stdin();

    for line in stdin.lines() {
        let line = match line {
            Ok(line) => line,
            Err(e) => {
                eprintln!("Failed to get line: {}", e);
                continue;
            }
        };

        let input_message: InputMessage = match serde_json::from_str(&line) {
            Ok(msg) => msg,
            Err(e) => {
                eprintln!("Failed to parse input: {}", e);
                continue;
            }
        };

        if input_message.message_type != "new" {
            let out = OutputMessage::new(
                input_message.event.id.clone(),
                Action::Reject,
                Some("invalid strfry write policy input".to_string()),
            );
            println!("{}", serialize_output_message(&out));
            continue;
        }

        let out = noteguard.run(input_message);
        let json = serialize_output_message(&out);

        println!("{}", json);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use noteguard::{Action, Note};

    // Helper function to create a mock InputMessage
    fn create_mock_input_message(
        event_id: &str,
        message_type: &str,
        source_info: &str,
    ) -> InputMessage {
        InputMessage {
            message_type: message_type.to_string(),
            event: Note {
                id: event_id.to_string(),
                pubkey: "mock_pubkey".to_string(),
                created_at: 0,
                kind: 1,
                tags: vec![vec!["-".to_string()]],
                content: "mock_content".to_string(),
                sig: "mock_signature".to_string(),
            },
            received_at: 0,
            source_type: "mock_source".to_string(),
            source_info: source_info.to_string(),
        }
    }

    #[test]
    fn test_register_builtin_filters() {
        let noteguard = Noteguard::new();
        assert!(noteguard.registered_filters.contains_key("ratelimit"));
        assert!(noteguard.registered_filters.contains_key("whitelist"));
        assert!(noteguard.registered_filters.contains_key("blacklist"));
        assert!(noteguard
            .registered_filters
            .contains_key("protected_events"));
        assert!(noteguard.registered_filters.contains_key("kinds"));
    }

    #[test]
    fn test_load_config() {
        let mut noteguard = Noteguard::new();

        // Create a mock config with one filter (RateLimit)
        let config: Config = toml::from_str(
            r#"
            pipeline = ["ratelimit"]

            [filters.ratelimit]
            posts_per_minute = 3
        "#,
        )
        .expect("Failed to parse config");

        assert!(noteguard.load_config(&config).is_ok());
        assert_eq!(noteguard.loaded_filters.len(), 1);
    }

    #[test]
    fn test_run_filters_accept() {
        let mut noteguard = Noteguard::new();

        // Create a mock config with one filter (RateLimit)
        let config: Config = toml::from_str(
            r#"
            pipeline = ["ratelimit"]

            [filters.ratelimit]
            posts_per_minute = 3
        "#,
        )
        .expect("Failed to parse config");

        noteguard
            .load_config(&config)
            .expect("Failed to load config");

        let input_message = create_mock_input_message("test_event_1", "new", "mock_source_info");
        let output_message = noteguard.run(input_message);

        assert_eq!(output_message.action, Action::Accept);
    }

    #[test]
    fn test_run_filters_shadow_reject() {
        let mut noteguard = Noteguard::new();

        // Create a mock config with one filter (ProtectedEvents) which will shadow reject the input
        let config: Config = toml::from_str(
            r#"
            pipeline = ["protected_events"]

            [filters.protected_events]
        "#,
        )
        .expect("Failed to parse config");

        noteguard
            .load_config(&config)
            .expect("Failed to load config");

        let input_message = create_mock_input_message("test_event_3", "new", "mock_source_info");
        let output_message = noteguard.run(input_message);

        assert_eq!(output_message.action, Action::Reject);
    }

    #[test]
    fn test_whitelist_reject() {
        let mut noteguard = Noteguard::new();

        // Create a mock config with one filter (Whitelist) which will reject the input
        let config: Config = toml::from_str(
            r#"
            pipeline = ["whitelist"]
            [filters.whitelist]
            pubkeys = ["something"]
        "#,
        )
        .expect("Failed to parse config");

        noteguard
            .load_config(&config)
            .expect("Failed to load config");

        let input_message = create_mock_input_message("test_event_2", "new", "mock_source_info");
        let output_message = noteguard.run(input_message);

        assert_eq!(output_message.action, Action::Reject);
    }

    #[test]
    fn test_blacklist_reject() {
        let mut noteguard = Noteguard::new();

        let config: Config = toml::from_str(
            r#"
            pipeline = ["blacklist"]
            [filters.blacklist]
            pubkeys = ["mock_pubkey"]
        "#,
        )
        .expect("Failed to parse config");

        noteguard
            .load_config(&config)
            .expect("Failed to load config");

        let input_message = create_mock_input_message("test_event_3", "new", "mock_source_info");
        let output_message = noteguard.run(input_message);

        assert_eq!(output_message.action, Action::Reject);
        assert_eq!(
            output_message.msg.expect("Failed to get message"),
            "blocked: pubkey/ip is blacklisted".to_string()
        );
    }

    #[test]
    fn test_blacklist_accept() {
        let mut noteguard = Noteguard::new();

        let config: Config = toml::from_str(
            r#"
            pipeline = ["blacklist"]
            [filters.blacklist]
            pubkeys = ["not_blacklisted"]
        "#,
        )
        .expect("Failed to parse config");

        noteguard
            .load_config(&config)
            .expect("Failed to load config");

        let input_message = create_mock_input_message("test_event_4", "new", "mock_source_info");
        let output_message = noteguard.run(input_message);

        assert_eq!(output_message.action, Action::Accept);
    }

    #[test]
    fn test_blacklist_cidr() {
        let mut noteguard = Noteguard::new();

        let config: Config = toml::from_str(
            r#"
            pipeline = ["blacklist"]
            [filters.blacklist]
            cidrs = ["127.0.0.1/24"]
        "#,
        )
        .expect("Failed to parse config");

        noteguard
            .load_config(&config)
            .expect("Failed to load config");

        let test_cases = [
            ("127.0.0.1", true),
            ("127.0.0.2", true),
            ("128.0.0.1", false),
            ("127.1.0.1", false),
            ("127.0.1.1", false),
        ];

        for (ip, should_reject) in test_cases.iter() {
            let input_message = create_mock_input_message("event_id", "new", ip);
            let output_message = noteguard.run(input_message);

            if *should_reject {
                assert_eq!(output_message.action, Action::Reject);
            } else {
                assert_eq!(output_message.action, Action::Accept);
            }
        }
    }

    // Helper to build a mock "new" message carrying arbitrary note content.
    fn create_mock_content_message(content: &str) -> InputMessage {
        let mut msg = create_mock_input_message("content_event", "new", "mock_source_info");
        msg.event.content = content.to_string();
        msg
    }

    #[test]
    fn test_content_filter_homoglyph() {
        let mut noteguard = Noteguard::new();

        let config: Config = toml::from_str(
            r#"
            pipeline = ["content"]
            [filters.content]
            filters = ["Damus Airdrop"]
        "#,
        )
        .expect("Failed to parse config");

        noteguard
            .load_config(&config)
            .expect("Failed to load config");

        // "Dаmus Аirdrop" — the 'а'/'А' are Cyrillic (U+0430/U+0410) homoglyphs,
        // the actual bytes seen in airdrop-scam spam. A raw substring check would
        // miss this; the confusables skeleton folds it back to "Damus Airdrop".
        let spam = "\u{1F680} D\u{0430}mus \u{0410}irdrop is open \u{00B7} \
                    Check your claim https://tinyurl.com/damuslive/";
        assert_eq!(
            noteguard.run(create_mock_content_message(spam)).action,
            Action::ShadowReject
        );

        // Plain ASCII match and a case variant both still get caught.
        assert_eq!(
            noteguard
                .run(create_mock_content_message("free Damus Airdrop here"))
                .action,
            Action::ShadowReject
        );
        assert_eq!(
            noteguard
                .run(create_mock_content_message("DAMUS AIRDROP!!!"))
                .action,
            Action::ShadowReject
        );

        // An unrelated note is accepted.
        assert_eq!(
            noteguard
                .run(create_mock_content_message("gm nostr, lovely morning"))
                .action,
            Action::Accept
        );
    }

    #[test]
    fn test_deserialize_input_message() {
        let input_json = r#"
        {
            "type": "new",
            "event": {
                "id": "test_event_5",
                "pubkey": "mock_pubkey",
                "created_at": 0,
                "kind": 1,
                "tags": [],
                "content": "mock_content",
                "sig": "mock_signature"
            },
            "receivedAt": 0,
            "sourceType": "mock_source",
            "sourceInfo": "mock_source_info"
        }
        "#;

        let input_message: InputMessage =
            serde_json::from_str(input_json).expect("Failed to deserialize input message");
        assert_eq!(input_message.event.id, "test_event_5");
        assert_eq!(input_message.message_type, "new");
    }
}
