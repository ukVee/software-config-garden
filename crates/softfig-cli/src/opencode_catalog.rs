//! The pre-launch catalog check for the semi-auto opencode loop
//! (opencode-v2-repin slice 002): is the resolved model (and variant) one that
//! opencode will actually route to?
//!
//! ## Why the launcher has to ask
//!
//! The interactive `opencode` root command has no `--model` flag, so the loop's
//! model rides the generated config's top-level `model`. On opencode 2.x a bad
//! top-level id does **not** fail. It silently falls back to `opencode/exo-free`
//! and sends the prompt there (slice 001, L7). An unknown variant is accepted at
//! config load as well: `deepseek/deepseek-flash#nosuchvariant` parsed cleanly on
//! a private server's `/api/config` (slice 002 probe). A typo in a `> Model:` line
//! would therefore run the loop on someone else's model without a word. The only
//! guard is to look the id up in opencode's own catalog first and refuse on a miss.
//!
//! ## How (each point is a probe finding on 2.0.24, slice 002)
//!
//! - **The one-shot forms are unusable.** `opencode models --standalone` printed
//!   nothing, and `opencode api --standalone model.list` returned `data: []`.
//!   A fresh server answers before its catalog has loaded.
//! - **The catalog fills in stages:** empty, then the connected providers'
//!   models, then everything. "Non-empty" therefore proves nothing, so the check
//!   polls until the wanted id appears. Only the deadline turns absence into a
//!   refusal.
//! - **The server is a private `opencode serve`** on loopback, behind a random
//!   password and loaded with the very config the session will run. A config that
//!   cannot load (a missing `{file:}` is an HTTP 500 for the whole location,
//!   slice 001 finding 8) fails the check too, instead of failing the session.
//!   It never touches the human's shared service.
//! - **The client is opencode's own `api --server … model.list`**, with the
//!   password in `OPENCODE_PASSWORD`, so softfig needs no HTTP client. One poll
//!   costs ~0.5 s of process startup, which is also what paces the loop.

use std::fs::File;
use std::io::Read;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use serde_json::Value;

/// How long the launcher waits for the wanted model to appear before refusing.
/// The full catalog took ~2–3 s on the Surface Go 3 (slice 002), so this leaves
/// room for a slow start without letting a typo hang the launch for long.
pub const CATALOG_DEADLINE: Duration = Duration::from_secs(20);

/// The pause between polls on top of each poll's own process startup.
const POLL_PAUSE: Duration = Duration::from_millis(250);

/// What one catalog reply says about a `provider/model` + optional variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatalogVerdict {
    /// The model is listed and, if a variant was asked for, offers it.
    Found,
    /// The model is not (or not yet) listed. `seen` is every `provider/model`
    /// the reply did list, for the refusal message.
    NoSuchModel { seen: Vec<String> },
    /// The model is listed but has no such variant. Final: a model's variants
    /// arrive with its catalog entry, so polling longer cannot change this.
    NoSuchVariant { variants: Vec<String> },
}

/// Judge one `model.list` reply (`{"data": [{providerID, id, variants: [{id}]}, …]}`)
/// against `model` (`provider/model`) and `variant`. Pure.
pub fn catalog_verdict(reply: &Value, model: &str, variant: Option<&str>) -> CatalogVerdict {
    let entries = reply["data"].as_array().map(Vec::as_slice).unwrap_or_default();
    let (provider, id) = model.split_once('/').unwrap_or(("", model));
    let entry = entries.iter().find(|e| {
        e["providerID"].as_str() == Some(provider)
            && (e["id"].as_str() == Some(id) || e["modelID"].as_str() == Some(id))
    });
    let Some(entry) = entry else {
        let seen = entries
            .iter()
            .filter_map(|e| Some(format!("{}/{}", e["providerID"].as_str()?, e["id"].as_str()?)))
            .collect();
        return CatalogVerdict::NoSuchModel { seen };
    };
    let Some(variant) = variant else {
        return CatalogVerdict::Found;
    };
    let variants: Vec<String> = entry["variants"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|v| v["id"].as_str().map(str::to_string))
        .collect();
    if variants.iter().any(|v| v == variant) {
        CatalogVerdict::Found
    } else {
        CatalogVerdict::NoSuchVariant { variants }
    }
}

/// Start a private opencode server on `config`, poll its catalog until `model`
/// (with `variant`) appears, and refuse if it does not by `deadline`. `Ok` means
/// opencode will route the launch to exactly the model the human chose.
pub fn verify_model(
    bin: &str,
    config: &Path,
    cwd: &Path,
    model: &str,
    variant: Option<&str>,
    deadline: Duration,
) -> Result<()> {
    let wanted = match variant {
        Some(v) => format!("{model}#{v}"),
        None => model.to_string(),
    };
    let until = Instant::now() + deadline;
    let port = free_loopback_port()?;
    let password = random_password()?;
    let mut server = ServerGuard(
        Command::new(bin)
            .args(["serve", "--hostname", "127.0.0.1", "--port", &port.to_string()])
            .env("OPENCODE_CONFIG", config)
            .env("OPENCODE_SERVER_PASSWORD", &password)
            .current_dir(cwd)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("starting a private `{bin} serve` for the catalog check"))?,
    );
    let url = format!("http://127.0.0.1:{port}");

    let mut seen: Vec<String> = Vec::new();
    loop {
        let mut poll = Command::new(bin);
        poll.args(["api", "--server", &url, "model.list"])
            .env("OPENCODE_PASSWORD", &password)
            .current_dir(cwd);
        // A failed poll (server not listening yet, not ready) is not a verdict;
        // only a parsed reply is.
        if let Some(reply) = run_until(poll, until)?
            .and_then(|out| serde_json::from_slice::<Value>(&out).ok())
        {
            match catalog_verdict(&reply, model, variant) {
                CatalogVerdict::Found => return Ok(()),
                CatalogVerdict::NoSuchVariant { variants } => bail!(
                    "opencode's catalog lists {model} but not variant `{}` (it has: {}). \
                     Refusing to launch: opencode accepts an unknown variant without \
                     complaint",
                    variant.unwrap_or_default(),
                    variants.join(", "),
                ),
                CatalogVerdict::NoSuchModel { seen: now } => seen = now,
            }
        }
        if let Some(status) = server.exited()? {
            bail!(
                "the private `{bin} serve` for the catalog check exited early ({status}); \
                 cannot confirm {wanted} is routable, so the launch is refused"
            );
        }
        if Instant::now() >= until {
            let listed = if seen.is_empty() {
                "it listed nothing".to_string()
            } else {
                format!("it lists: {}", seen.join(", "))
            };
            bail!(
                "{wanted} is not in opencode's catalog after {}s ({listed}). Refusing to \
                 launch: on opencode 2.x an unknown top-level model silently falls back to \
                 opencode/exo-free and sends the prompt there",
                deadline.as_secs(),
            );
        }
        thread::sleep(POLL_PAUSE);
    }
}

/// The private catalog server, killed and reaped however the check ends.
struct ServerGuard(Child);

impl ServerGuard {
    fn exited(&mut self) -> Result<Option<std::process::ExitStatus>> {
        self.0.try_wait().context("polling the catalog server")
    }
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Run `cmd` to completion and return its stdout, or `None` if it failed or was
/// still running at `until` (in which case it is killed). stdout is drained on a
/// thread so a large catalog cannot fill the pipe and wedge the child.
fn run_until(mut cmd: Command, until: Instant) -> Result<Option<Vec<u8>>> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .context("running `opencode api` for the catalog check")?;
    let mut stdout = child.stdout.take().expect("stdout is piped");
    let reader = thread::spawn(move || {
        let mut buf = Vec::new();
        stdout.read_to_end(&mut buf).map(|_| buf)
    });
    let status = loop {
        if let Some(status) = child.try_wait().context("waiting on `opencode api`")? {
            break Some(status);
        }
        if Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        thread::sleep(Duration::from_millis(50));
    };
    let out = reader
        .join()
        .map_err(|_| anyhow!("the `opencode api` reader thread panicked"))?
        .context("reading `opencode api` output")?;
    Ok(status.filter(|s| s.success()).map(|_| out))
}

/// A loopback port free right now. The bind is dropped before opencode binds it,
/// so the window is tiny; losing the race makes the server exit, which the check
/// reports as a refusal rather than guessing.
fn free_loopback_port() -> Result<u16> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).context("finding a free loopback port")?;
    Ok(listener.local_addr()?.port())
}

/// A one-shot password for the private server, so nothing else on the machine can
/// talk to it while it is up.
fn random_password() -> Result<String> {
    let mut bytes = [0u8; 16];
    File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(&mut bytes))
        .context("reading /dev/urandom for the catalog server password")?;
    Ok(hex::encode(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A trimmed real `model.list` reply from opencode 2.0.24 (slice 002 probe):
    /// the two connected DeepSeek models with their variants, plus one opencode
    /// free model, which arrives later in the staged fill.
    fn reply() -> Value {
        serde_json::json!({
            "location": {"directory": "/garden"},
            "data": [
                {"id": "deepseek-flash", "modelID": "deepseek-flash", "providerID": "deepseek",
                 "variants": [{"id": "none"}, {"id": "low"}, {"id": "high"}, {"id": "max"}]},
                {"id": "deepseek-v4-pro", "modelID": "deepseek-v4-pro", "providerID": "deepseek",
                 "variants": [{"id": "none"}, {"id": "low"}, {"id": "high"}, {"id": "max"}]},
                {"id": "exo-free", "modelID": "exo-free", "providerID": "opencode", "variants": []}
            ]
        })
    }

    #[test]
    fn a_listed_model_with_a_listed_variant_is_found() {
        assert_eq!(catalog_verdict(&reply(), "deepseek/deepseek-flash", None), CatalogVerdict::Found);
        assert_eq!(
            catalog_verdict(&reply(), "deepseek/deepseek-v4-pro", Some("high")),
            CatalogVerdict::Found,
        );
    }

    #[test]
    fn the_retired_flash_id_is_not_found_and_the_refusal_lists_what_is() {
        // slice 001 finding 12: `deepseek-v4-flash` left the 2.x catalog.
        match catalog_verdict(&reply(), "deepseek/deepseek-v4-flash", None) {
            CatalogVerdict::NoSuchModel { seen } => assert_eq!(
                seen,
                ["deepseek/deepseek-flash", "deepseek/deepseek-v4-pro", "opencode/exo-free"],
            ),
            other => panic!("expected NoSuchModel, got {other:?}"),
        }
    }

    #[test]
    fn the_provider_must_match_not_just_the_model_name() {
        assert!(matches!(
            catalog_verdict(&reply(), "opencode/deepseek-flash", None),
            CatalogVerdict::NoSuchModel { .. }
        ));
    }

    #[test]
    fn an_unknown_variant_is_final_and_names_the_real_ones() {
        // `thinking` was this repo's example variant on 1.18; DeepSeek's 2.x
        // variants are none/low/high/max.
        assert_eq!(
            catalog_verdict(&reply(), "deepseek/deepseek-flash", Some("thinking")),
            CatalogVerdict::NoSuchVariant {
                variants: vec!["none".into(), "low".into(), "high".into(), "max".into()],
            },
        );
    }

    #[test]
    fn an_empty_or_unloaded_catalog_is_not_found_yet_never_found() {
        // The fresh-server answer (`data: []`) and a malformed reply both mean "keep
        // polling", never a pass.
        for r in [serde_json::json!({"data": []}), serde_json::json!({}), Value::Null] {
            assert_eq!(
                catalog_verdict(&r, "deepseek/deepseek-flash", None),
                CatalogVerdict::NoSuchModel { seen: vec![] },
            );
        }
    }
}
