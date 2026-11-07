//! `softfig telemetry` — token telemetry (garden `meta/spec-token-telemetry.md`).
//!
//! Phase 1 has one verb: `ingest-transcript`, the semi-auto capture point
//! (spec §4.2). The generated growlight `loop.json` runs it from claude's
//! `SessionEnd` hook, which hands it `{session_id, transcript_path, …}` on
//! stdin; `--path` ingests a transcript by hand (a backfill). Either way the
//! session's rows are priced and written in one idempotent batch, so running
//! it twice over the same transcript adds nothing.
//!
//! The hook must never fail a session: the verb always exits 0 and reports
//! problems on stderr only.

use std::fs::File;
use std::io::{BufReader, IsTerminal, Read};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use clap::{Args, Subcommand};
use serde::Deserialize;
use softfig_ipc::baton::parse_baton;
use softfig_ipc::runtime_socket_path;
use softfig_telemetry::{
    PriceTable, RequestRow, Store, TranscriptKeys, default_db_path, ingest_transcript,
    renumber_turns,
};

use crate::cmd_growlight;

/// The `member` every semi-auto row carries (spec §4.2).
const SEMI_AUTO_MEMBER: &str = "semi-auto";

#[derive(Subcommand, Debug)]
pub enum TelemetryCmd {
    /// Ingest a claude session transcript into the telemetry db — the
    /// `SessionEnd` hook's verb. Reads the hook's JSON from stdin unless
    /// `--path` names a transcript. Idempotent; always exits 0.
    IngestTranscript(IngestArgs),
}

#[derive(Args, Debug)]
pub struct IngestArgs {
    /// A transcript JSONL to ingest instead of reading the hook's stdin.
    #[arg(long)]
    pub path: Option<PathBuf>,
    /// The session id for lines that name none (default: the hook's
    /// `session_id`, else the transcript file's stem).
    #[arg(long)]
    pub session_id: Option<String>,
    /// The telemetry db (default `$XDG_STATE_HOME/softfig/telemetry.db`).
    #[arg(long)]
    pub db: Option<PathBuf>,
    /// The garden root to read `config/pricing.toml` from (default: asked of
    /// the running daemon; rows store null cost when neither answers).
    #[arg(long)]
    pub garden_root: Option<PathBuf>,
    /// The growlight runtime dir holding the root `baton.md` whose `item:`
    /// keys the rows (default `$XDG_CONFIG_HOME/softfig/growlight`).
    #[arg(long)]
    pub config_dir: Option<PathBuf>,
}

pub fn run(cmd: TelemetryCmd) -> Result<()> {
    match cmd {
        TelemetryCmd::IngestTranscript(args) => {
            match ingest(args, unix_now()) {
                Ok(n) => eprintln!("telemetry: ingested {n} new request row(s)"),
                Err(e) => eprintln!("telemetry: ingest-transcript failed: {e:#}"),
            }
            Ok(())
        }
    }
}

/// The fields the `SessionEnd` hook input carries that ingest reads.
#[derive(Debug, Deserialize)]
struct HookInput {
    transcript_path: Option<PathBuf>,
    session_id: Option<String>,
}

fn ingest(args: IngestArgs, now: i64) -> Result<usize> {
    let (transcript, hook_session) = match &args.path {
        Some(p) => (p.clone(), None),
        None => {
            let stdin = std::io::stdin();
            if stdin.is_terminal() {
                return Err(anyhow!("no --path and no hook input on stdin"));
            }
            let mut raw = String::new();
            stdin.lock().read_to_string(&mut raw).context("reading hook stdin")?;
            let hook: HookInput = serde_json::from_str(&raw).context("parsing hook stdin")?;
            let path = hook
                .transcript_path
                .ok_or_else(|| anyhow!("hook input carries no transcript_path"))?;
            (path, hook.session_id)
        }
    };
    let baton = cmd_growlight::runtime_dir(args.config_dir.clone())
        .ok()
        .and_then(|dir| std::fs::read_to_string(dir.join("baton.md")).ok())
        .map(|text| parse_baton(&text));
    let keys = TranscriptKeys {
        member: SEMI_AUTO_MEMBER.to_string(),
        session_id: args.session_id.or(hook_session).or_else(|| {
            transcript.file_stem().map(|s| s.to_string_lossy().into_owned())
        }),
        profile: profile_slot(std::env::var_os("CLAUDE_CONFIG_DIR").as_deref().map(Path::new)),
        item_id: baton.as_ref().and_then(|b| b.item.clone()),
        // A baton head may quote the slice (`slice: "005"`); the key is bare.
        slice_id: baton.and_then(|b| b.slice).map(|s| s.trim_matches('"').to_string()),
        queue: None,
    };
    let mut rows = Vec::new();
    for file in transcript_files(&transcript) {
        match File::open(&file) {
            Ok(f) => rows.extend(ingest_transcript(BufReader::new(f), &keys, now)),
            // The main transcript must be there; a subagent file that vanished
            // under us costs only its own rows.
            Err(e) if file == transcript => {
                return Err(anyhow!("opening {}: {e}", file.display()));
            }
            Err(e) => eprintln!("telemetry: skipping {}: {e}", file.display()),
        }
    }
    renumber_turns(&mut rows);
    price(&mut rows, args.garden_root);
    let db = args
        .db
        .or_else(default_db_path)
        .ok_or_else(|| anyhow!("no telemetry db path ($XDG_STATE_HOME / $HOME unset)"))?;
    let mut store = Store::open(&db).with_context(|| format!("opening {}", db.display()))?;
    let new = store.insert_batch(&rows)?;
    // This verb is the only writer on a device whose fleet is disarmed, so it
    // carries the retention sweep the flush thread would run: a backfill's old
    // rows roll up now, and a long-lived db keeps to its 90 days. The rows are
    // in; a failed sweep is reported and never fails the ingest.
    if let Err(e) = store.sweep_retention(now) {
        eprintln!("telemetry: retention sweep failed: {e}");
    }
    Ok(new)
}

/// The main transcript, then its subagents' (`<dir>/<stem>/subagents/*.jsonl`,
/// where current claude writes a subagent's lines), sorted for a stable order.
fn transcript_files(transcript: &Path) -> Vec<PathBuf> {
    let mut subs: Vec<PathBuf> = transcript
        .file_stem()
        .map(|stem| transcript.with_file_name(stem).join("subagents"))
        .and_then(|dir| std::fs::read_dir(dir).ok())
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "jsonl"))
        .collect();
    subs.sort();
    std::iter::once(transcript.to_path_buf()).chain(subs).collect()
}

/// Price each row from the garden's `config/pricing.toml`. A garden that can't
/// be found or a table that won't parse leaves every cost null, never 0.
fn price(rows: &mut [RequestRow], garden_root: Option<PathBuf>) {
    let garden = match garden_root {
        Some(g) => g,
        None => match cmd_growlight::resolve_garden_root(&runtime_socket_path(), None) {
            Ok(g) => g,
            Err(e) => {
                eprintln!("telemetry: rows stored unpriced (no garden: {e})");
                return;
            }
        },
    };
    match PriceTable::load(&garden) {
        Ok(table) => rows.iter_mut().for_each(|r| table.price_row(r)),
        Err(e) => eprintln!("telemetry: rows stored unpriced ({e})"),
    }
}

/// The claude login slot a `CLAUDE_CONFIG_DIR` names: its last component, as
/// the statusline tags snapshots. `None` for unset or `home`, as on a
/// growlightd row.
fn profile_slot(config_dir: Option<&Path>) -> Option<String> {
    let slot = config_dir?.file_name()?.to_string_lossy().into_owned();
    (!slot.is_empty() && slot != "home").then_some(slot)
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRANSCRIPT: &str =
        include_str!("../../softfig-telemetry/tests/fixtures/claude-transcript.jsonl");
    /// An hour after the fixture's last line, so retention never drops it.
    const NOW: i64 = 1_793_473_200;

    #[test]
    fn the_profile_is_the_config_dirs_slot_and_home_is_none() {
        let store = "/home/u/.local/share/softfig/claude-profiles/slot2";
        assert_eq!(profile_slot(Some(Path::new(store))).as_deref(), Some("slot2"));
        assert_eq!(profile_slot(Some(Path::new("/x/home"))), None);
        assert_eq!(profile_slot(None), None);
    }

    #[test]
    fn subagent_transcripts_follow_the_main_one() {
        let dir = tempfile::tempdir().unwrap();
        let main = dir.path().join("sess.jsonl");
        std::fs::write(&main, "").unwrap();
        let subs = dir.path().join("sess/subagents");
        std::fs::create_dir_all(&subs).unwrap();
        for f in ["agent-b.jsonl", "agent-a.jsonl", "notes.txt"] {
            std::fs::write(subs.join(f), "").unwrap();
        }
        assert_eq!(
            transcript_files(&main),
            [main.clone(), subs.join("agent-a.jsonl"), subs.join("agent-b.jsonl")]
        );
        assert_eq!(transcript_files(&dir.path().join("none.jsonl")).len(), 1);
    }

    #[test]
    fn a_path_ingest_keys_from_the_baton_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let transcript = dir.path().join("sess-t.jsonl");
        std::fs::write(&transcript, TRANSCRIPT).unwrap();
        let cfg = dir.path().join("growlight");
        std::fs::create_dir_all(&cfg).unwrap();
        std::fs::write(
            cfg.join("baton.md"),
            "---\nstatus: IN_PROGRESS\nitem: token-telemetry-p1\nslice: \"005\"\n---\n",
        )
        .unwrap();
        let garden = dir.path().join("garden");
        std::fs::create_dir_all(garden.join("config")).unwrap();
        let db = dir.path().join("telemetry.db");
        let args = || IngestArgs {
            path: Some(transcript.clone()),
            session_id: None,
            db: Some(db.clone()),
            garden_root: Some(garden.clone()),
            config_dir: Some(cfg.clone()),
        };
        // No pricing.toml: rows still land, unpriced.
        assert_eq!(ingest(args(), NOW).unwrap(), 3);
        assert_eq!(ingest(args(), NOW).unwrap(), 0, "a re-ingest adds nothing");
        let conn = rusqlite::Connection::open(&db).unwrap();
        let (member, item, slice, settled): (String, String, String, String) = conn
            .query_row(
                "select distinct member, item_id, slice_id, settled_from from requests",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .unwrap();
        assert_eq!(
            (member.as_str(), item.as_str(), slice.as_str(), settled.as_str()),
            ("semi-auto", "token-telemetry-p1", "005", "transcript")
        );
    }

    #[test]
    fn a_backfill_past_retention_rolls_up_and_a_re_ingest_adds_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let transcript = dir.path().join("sess-t.jsonl");
        std::fs::write(&transcript, TRANSCRIPT).unwrap();
        let db = dir.path().join("telemetry.db");
        let args = || IngestArgs {
            path: Some(transcript.clone()),
            session_id: None,
            db: Some(db.clone()),
            garden_root: Some(dir.path().to_path_buf()),
            config_dir: Some(dir.path().to_path_buf()),
        };
        // No flusher runs here, as on a disarmed device: the verb sweeps.
        let later = NOW + 100 * 86_400;
        assert_eq!(ingest(args(), later).unwrap(), 3);
        assert_eq!(ingest(args(), later).unwrap(), 0, "rolled-up history is not re-counted");
        let conn = rusqlite::Connection::open(&db).unwrap();
        let (raw, rolled): (i64, i64) = conn
            .query_row(
                "select (select count(*) from requests),
                        (select coalesce(sum(requests), 0) from daily_rollup)",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((raw, rolled), (0, 3), "all three requests are in the rollup, once");
    }

    #[test]
    fn a_missing_transcript_is_an_error_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let err = ingest(IngestArgs {
            path: Some(dir.path().join("gone.jsonl")),
            session_id: None,
            db: Some(dir.path().join("t.db")),
            garden_root: Some(dir.path().to_path_buf()),
            config_dir: Some(dir.path().to_path_buf()),
        }, NOW)
        .unwrap_err();
        assert!(err.to_string().contains("gone.jsonl"), "{err}");
    }
}
