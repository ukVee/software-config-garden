//! growlight peer-isolation slice 003 — persist the live build-resource caps
//! default into the in-garden `config/growlight.toml` `[build_caps]` table.
//!
//! Slice 003a-live made the GENTLE per-agent caps (`CARGO_BUILD_JOBS` /
//! `MemoryHigh` / `CPUWeight`) live-adjustable in growlightd's RAM + on running
//! agent scopes. But growlightd re-reads `config/growlight.toml` on every
//! restart, so a live change is lost — finish-criterion 4 wants a **persisted
//! config default**, written through keeperd's commit path (an MCP-mediated
//! commit, never a raw mount write).
//!
//! This is that persist. growlightd (after a successful live `set_resources`)
//! best-effort calls the `growlight_set_resources` IPC verb; the daemon
//! surgically updates the `[build_caps]` table — preserving the heavy comments
//! and the rest of the fleet config (`fleet_enabled` / `claude_bin` / `prompt` /
//! `[[fleet]]`) via `toml_edit`, creating the table if absent — and folds the
//! change into one `growlight_resources_set` commit. An idempotent re-persist of
//! the current caps produces byte-identical content and mints no commit (mirrors
//! `set_item_status`). The surgery itself ([`apply_build_caps`]) is a pure
//! function, unit-tested without a daemon. See
//! `journal/decisions/decision-growlight-resources-persist.md`.
//!
//! **Throttle-not-kill.** The wire args (and so the persisted keys) carry only
//! the three SOFT knobs — there is no `MemoryMax`/hard-cap key — so a persisted
//! change can only ever slow a build, never abort it.

use toml_edit::{value, DocumentMut, Item, Table};

use softfig_ipc::verbs::{GrowlightSetResourcesArgs, GrowlightSetResourcesReply};
use softfig_ipc::ErrorKind;
use softfig_vcs::Intent;

use super::super::{commit_now, WorkTree};
use crate::daemon::{Daemon, DaemonInner};
use crate::handlers::{require_unlocked, HandlerResult};
use crate::server::err_to_response;

/// The `[build_caps]` table name in `config/growlight.toml`.
const BUILD_CAPS_TABLE: &str = "build_caps";

/// The comment block prepended when the `[build_caps]` table is created fresh
/// (it doesn't ship in the default template — a missing table means defaults).
/// Matches the heavily-commented house style of the rest of the file.
const FRESH_TABLE_PREFIX: &str = "\n\
# Live GENTLE per-agent build-resource caps (peer-isolation slice 003),\n\
# persisted by `growlight resources set` so a live change survives a daemon\n\
# restart. Throttle-not-kill: only soft knobs — a low CARGO_BUILD_JOBS, a soft\n\
# MemoryHigh (NOT MemoryMax/OOM-kill), an optional CPUWeight. A missing key is\n\
# left unset (the default applies).\n";

/// The garden-relative path of the fleet config the caps live in.
fn config_rel() -> String {
    format!(
        "{}/{}",
        softfig_ipc::GARDEN_CONFIG_DIR,
        softfig_ipc::GROWLIGHT_CONFIG_FILE
    )
}

pub fn growlight_set_resources(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: GrowlightSetResourcesArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("growlight_set_resources args: {e}")))?;

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let rel = config_rel();
    {
        let wt = WorkTree::new(daemon, &inner);
        if !wt.exists(&rel) {
            return Err((
                ErrorKind::NotFound,
                format!("{rel}: absent; run `softfig growlight init` first"),
            ));
        }
        let current = crate::actions::sections::read_if_unprotected(&wt, &inner, &rel).ok_or((
            ErrorKind::VaultProtected,
            format!("{rel}: unreadable or vault-protected"),
        ))?;
        let updated = apply_build_caps(&current, &args)
            .map_err(|e| (ErrorKind::BadArgs, format!("{rel}: {e}")))?;

        // Idempotent: byte-identical surgery (a re-persist of the current caps)
        // makes no tree change → return the current tip, mint no commit.
        if updated == current {
            let tip = current_tip(&inner)?;
            return Ok(serde_json::to_value(GrowlightSetResourcesReply {
                committed: false,
                hash: tip,
                path: rel,
            })
            .unwrap());
        }
        wt.write(&rel, updated.as_bytes())?;
    }

    let payload = serde_json::json!({
        "cargo_build_jobs": args.cargo_build_jobs,
        "memory_high": args.memory_high,
        "cpu_weight": args.cpu_weight,
    });
    // The intent is spelled `growlight_resources_set` (verb-last) while the IPC op
    // is `growlight_set_resources` — the inversion is intentional, not a cross-wire
    // (slice 008; see softfig_ipc::verbs::op::GROWLIGHT_SET_RESOURCES).
    let intent = Intent::new("growlight_resources_set", payload)
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let hash = commit_now(&mut inner, intent)?;

    Ok(serde_json::to_value(GrowlightSetResourcesReply {
        committed: true,
        hash: hash.to_string(),
        path: rel,
    })
    .unwrap())
}

/// The current tip as a hex string (empty if there are no commits yet).
fn current_tip(inner: &DaemonInner) -> Result<String, (ErrorKind, String)> {
    Ok(inner
        .repo
        .as_ref()
        .expect("unlocked")
        .tip()
        .map_err(|e| err_to_response(e.into()))?
        .map(|h| h.to_string())
        .unwrap_or_default())
}

/// Surgically apply the desired `[build_caps]` state to `current` and return the
/// re-rendered document. Pure (no I/O): parse with `toml_edit`, create the
/// `[build_caps]` table if absent (with a leading comment), then for each key
/// **set** it if `Some` / **remove** it if `None`. Everything else in the file —
/// the comments, `fleet_enabled`, `claude_bin`, `prompt`, every `[[fleet]]`
/// block — is byte-preserved. Returns the parse error string on malformed input.
fn apply_build_caps(current: &str, caps: &GrowlightSetResourcesArgs) -> Result<String, String> {
    let mut doc = current
        .parse::<DocumentMut>()
        .map_err(|e| format!("not valid TOML: {e}"))?;

    let fresh = !doc.contains_key(BUILD_CAPS_TABLE);
    let table = doc
        .entry(BUILD_CAPS_TABLE)
        .or_insert(Item::Table(Table::new()))
        .as_table_mut()
        .ok_or_else(|| format!("`[{BUILD_CAPS_TABLE}]` exists but is not a table"))?;
    if fresh {
        table.decor_mut().set_prefix(FRESH_TABLE_PREFIX);
    }

    set_or_remove(table, "cargo_build_jobs", caps.cargo_build_jobs.map(|v| value(v as i64)));
    set_or_remove(table, "memory_high", caps.memory_high.clone().map(value));
    set_or_remove(table, "cpu_weight", caps.cpu_weight.map(|v| value(v as i64)));

    Ok(doc.to_string())
}

/// Set `key` to `item` when `Some`, or remove it when `None` — the per-knob
/// upsert that lets the persisted table mirror the live caps exactly (an unset
/// cap leaves no stale key behind).
///
/// Note (slice 008): the `None`/remove branch is **unreachable in practice** today
/// — growlightd always persists the FULL merged caps (every field `Some`), and even
/// a removed key would be refilled on reload by `FleetConfig`'s all-`Some`
/// `BuildCaps` default. It's kept (and unit-tested) so the surgery faithfully
/// mirrors whatever args it's given, but no current caller produces a `None`, and a
/// cap can never become runtime-unset by design (there is always a throttle).
fn set_or_remove(table: &mut Table, key: &str, item: Option<Item>) {
    match item {
        Some(it) => {
            table.insert(key, it);
        }
        None => {
            table.remove(key);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixture shaped like the shipped template: top-level keys + heavy
    /// comments + a commented `[[fleet]]` block, and NO `[build_caps]` table.
    const TEMPLATE: &str = "# soft-fig growlight fleet config.\n\
\n\
# The gate.\n\
fleet_enabled = false\n\
\n\
# claude_bin = \"claude\"\n\
\n\
# [[fleet]]\n\
# agent = \"a\"\n";

    fn args(jobs: Option<u32>, mem: Option<&str>, cpu: Option<u32>) -> GrowlightSetResourcesArgs {
        GrowlightSetResourcesArgs {
            cargo_build_jobs: jobs,
            memory_high: mem.map(|s| s.to_string()),
            cpu_weight: cpu,
        }
    }

    #[test]
    fn creates_the_table_when_absent_preserving_everything_else() {
        let out = apply_build_caps(TEMPLATE, &args(Some(2), Some("3G"), Some(50))).unwrap();
        // Every pre-existing line + comment survives untouched.
        assert!(out.contains("# soft-fig growlight fleet config."));
        assert!(out.contains("fleet_enabled = false"));
        assert!(out.contains("# claude_bin = \"claude\""));
        assert!(out.contains("# [[fleet]]"));
        // The table was created with all three knobs.
        assert!(out.contains("[build_caps]"));
        assert!(out.contains("cargo_build_jobs = 2"));
        assert!(out.contains("memory_high = \"3G\""));
        assert!(out.contains("cpu_weight = 50"));
        // It re-parses as valid TOML.
        out.parse::<DocumentMut>().expect("valid toml");
    }

    #[test]
    fn updates_existing_keys_in_place_preserving_comments() {
        let once = apply_build_caps(TEMPLATE, &args(Some(2), Some("3G"), Some(50))).unwrap();
        let twice = apply_build_caps(&once, &args(Some(4), Some("4G"), Some(80))).unwrap();
        assert!(twice.contains("cargo_build_jobs = 4"));
        assert!(twice.contains("memory_high = \"4G\""));
        assert!(twice.contains("cpu_weight = 80"));
        assert!(!twice.contains("= 2"), "old value gone: {twice}");
        // Still one table, comments intact.
        assert_eq!(twice.matches("[build_caps]").count(), 1);
        assert!(twice.contains("fleet_enabled = false"));
    }

    #[test]
    fn a_none_knob_removes_the_key() {
        let full = apply_build_caps(TEMPLATE, &args(Some(2), Some("3G"), Some(50))).unwrap();
        assert!(full.contains("cpu_weight = 50"));
        // Persist with cpu_weight unset → the key is dropped, the others stay.
        let trimmed = apply_build_caps(&full, &args(Some(2), Some("3G"), None)).unwrap();
        assert!(!trimmed.contains("cpu_weight"), "key removed: {trimmed}");
        assert!(trimmed.contains("cargo_build_jobs = 2"));
        assert!(trimmed.contains("memory_high = \"3G\""));
    }

    #[test]
    fn re_persisting_the_same_caps_is_byte_identical() {
        // The idempotency contract the handler's no-commit guard relies on: the
        // same desired state re-rendered equals the prior output exactly.
        let once = apply_build_caps(TEMPLATE, &args(Some(2), Some("3G"), Some(50))).unwrap();
        let twice = apply_build_caps(&once, &args(Some(2), Some("3G"), Some(50))).unwrap();
        assert_eq!(once, twice);
    }

    #[test]
    fn malformed_toml_is_an_error_not_a_panic() {
        let err = apply_build_caps("this is = = not toml", &args(Some(2), None, None)).unwrap_err();
        assert!(err.contains("not valid TOML"), "{err}");
    }
}
