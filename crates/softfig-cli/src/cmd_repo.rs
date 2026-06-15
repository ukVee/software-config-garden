use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use clap::Args;
use softfig_ipc::verbs::{
    op, CommitArgs as IpcCommitArgs, FsckReply, LogArgs as IpcLogArgs, LogReply,
    ShowArgs as IpcShowArgs, ShowReply,
};
use softfig_store::{Hash, TreeEntryKind};
use softfig_vault::{discover_garden, Vault};
use softfig_vcs::{fsck as run_fsck, log_collect, FsckReport, Intent, Repo, KNOWN_INTENTS};

use crate::cmd_daemon::try_daemon_call;

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Garden root. Defaults to the current directory.
    #[arg(long)]
    pub garden: Option<PathBuf>,
}

#[derive(Args, Debug)]
pub struct CommitArgs {
    /// Garden root. Defaults to the discovered .softfig/ ancestor.
    #[arg(long)]
    pub garden: Option<PathBuf>,
    /// Closed-enum intent. Run `softfig commit --help` to see the list.
    #[arg(long, value_parser = parse_intent_name)]
    pub intent: String,
    /// Commit message / summary.
    #[arg(short, long)]
    pub message: Option<String>,
    /// Repo-relative paths the commit relates to. Repeatable. Folded into
    /// the payload as the `files` field. Optional; only some intents use
    /// it (`memory_edit`, `schema_change`).
    #[arg(short, long = "file")]
    pub files: Vec<String>,
    /// Free-form payload key=value pairs. Repeatable. Stored as-is in the
    /// payload (string values). For richer payloads, use `--payload-json`.
    #[arg(long = "kv")]
    pub kvs: Vec<String>,
    /// Inline JSON object passed verbatim as the payload. Overrides
    /// --message/--file/--kv if set. Useful for `rollback`,
    /// `archive_move`, etc.
    #[arg(long)]
    pub payload_json: Option<String>,
}

#[derive(Args, Debug)]
pub struct LogArgs {
    #[arg(long)]
    pub garden: Option<PathBuf>,
    /// Maximum number of commits to print. 0 = no limit.
    #[arg(long, default_value_t = 0)]
    pub limit: usize,
}

#[derive(Args, Debug)]
pub struct ShowArgs {
    #[arg(long)]
    pub garden: Option<PathBuf>,
    /// Commit hash (hex). Defaults to tip.
    pub commit: Option<String>,
}

#[derive(Args, Debug)]
pub struct FsckArgs {
    #[arg(long)]
    pub garden: Option<PathBuf>,
}

// ---- subcommand entry points ----

pub fn init(args: InitArgs) -> Result<()> {
    let garden = resolve_for_init(args.garden)?;
    let vault = Vault::at(&garden);
    if !vault.is_initialized() {
        return Err(anyhow!(
            "no vault at {}; run `softfig vault init --garden {}` first",
            vault.paths().root.display(),
            garden.display()
        ));
    }
    let pass = prompt_passphrase("Vault passphrase: ")?;
    let session = vault.unlock(pass.as_bytes())?;

    let (_repo, genesis) = Repo::init(&garden, &session)?;
    println!("Initialized softfig repo at {}/.softfig/", garden.display());
    println!("  genesis commit : {genesis}");
    Ok(())
}

pub fn commit(args: CommitArgs) -> Result<()> {
    let payload = build_payload(&args)?;
    let intent_name = args.intent.clone();
    let garden = resolve_existing(args.garden)?;

    // Bridge fast path: try the daemon first.
    let socket = softfig_ipc::runtime_socket_path();
    let req_args = serde_json::to_value(IpcCommitArgs {
        intent: intent_name.clone(),
        payload: payload.clone(),
    })?;
    if let Some(reply) =
        try_daemon_call(&socket, op::COMMIT, req_args).map_err(|e| anyhow!("daemon: {e}"))?
    {
        let hash = reply
            .get("hash")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("daemon reply missing 'hash'"))?;
        println!("Committed: {hash}");
        return Ok(());
    }

    // Direct mode (only reached when socket is absent).
    forbid_direct_mode_when_migrated(&garden)?;
    let vault = Vault::at(&garden);
    let pass = prompt_passphrase("Vault passphrase: ")?;
    let session = vault.unlock(pass.as_bytes())?;

    let intent = Intent::new(&intent_name, payload)
        .with_context(|| format!("invalid intent {intent_name:?}"))?;

    let mut repo = Repo::open(&garden)?;
    let hash = repo.commit_workdir(&session, intent)?;
    println!("Committed: {hash}");
    Ok(())
}

pub fn log(args: LogArgs) -> Result<()> {
    let garden = resolve_existing(args.garden)?;

    let socket = softfig_ipc::runtime_socket_path();
    let req_args = serde_json::to_value(IpcLogArgs { limit: args.limit })?;
    if let Some(reply) =
        try_daemon_call(&socket, op::LOG, req_args).map_err(|e| anyhow!("daemon: {e}"))?
    {
        let log_reply: LogReply = serde_json::from_value(reply)?;
        if log_reply.commits.is_empty() {
            println!("(no commits)");
            return Ok(());
        }
        for c in &log_reply.commits {
            println!(
                "{} {} {} {}",
                c.hash,
                iso8601(c.timestamp),
                c.intent,
                c.summary,
            );
        }
        return Ok(());
    }

    forbid_direct_mode_when_migrated(&garden)?;
    let repo = Repo::open(&garden)?;
    let tip = match repo.tip()? {
        Some(h) => h,
        None => {
            println!("(no commits)");
            return Ok(());
        }
    };
    let commits = log_collect(repo.db(), tip)?;
    let limit = if args.limit == 0 {
        commits.len()
    } else {
        args.limit.min(commits.len())
    };
    for c in commits.iter().take(limit) {
        println!(
            "{} {} {} {}",
            c.hash,
            iso8601(c.timestamp),
            c.intent,
            short_summary(&c.payload),
        );
    }
    Ok(())
}

pub fn show(args: ShowArgs) -> Result<()> {
    let garden = resolve_existing(args.garden)?;

    let socket = softfig_ipc::runtime_socket_path();
    let req_args = serde_json::to_value(IpcShowArgs {
        hash: args.commit.clone(),
    })?;
    if let Some(reply) =
        try_daemon_call(&socket, op::SHOW, req_args).map_err(|e| anyhow!("daemon: {e}"))?
    {
        let show: ShowReply = serde_json::from_value(reply)?;
        let c = &show.commit;
        println!("commit          {}", c.hash);
        if let Some(p) = &c.parent {
            println!("parent          {p}");
        } else {
            println!("parent          (genesis)");
        }
        println!("root_tree       {}", c.root_tree);
        println!("author_device   {}", c.author_device);
        println!("author_pubkey   {}", c.author_pubkey_hex);
        println!("timestamp       {} ({})", c.timestamp, iso8601(c.timestamp));
        println!("intent          {}", c.intent);
        println!("master_key_id   {}", c.master_key_id);
        println!("signature       {}", c.signature_hex);
        println!("payload         {}", c.payload);
        println!();
        println!("root tree:");
        for e in &show.root_tree {
            let marker = if e.kind == "tree" { "tree/" } else { "blob " };
            println!("  {marker} {:o} {}  {}", e.mode, e.target_hex, e.name);
        }
        return Ok(());
    }

    forbid_direct_mode_when_migrated(&garden)?;
    let repo = Repo::open(&garden)?;
    let target = match args.commit {
        Some(s) => Hash::from_hex(&s)?,
        None => repo
            .tip()?
            .ok_or_else(|| anyhow!("no commits in this repo yet"))?,
    };
    let row = repo.db().get_commit(&target)?;
    println!("commit          {}", row.hash);
    if let Some(p) = row.parent {
        println!("parent          {p}");
    } else {
        println!("parent          (genesis)");
    }
    println!("root_tree       {}", row.root_tree);
    println!("author_device   {}", row.author_device);
    println!("author_pubkey   {}", hex::encode(row.author_pubkey));
    println!(
        "timestamp       {} ({})",
        row.timestamp,
        iso8601(row.timestamp)
    );
    println!("intent          {}", row.intent);
    println!("master_key_id   {}", row.master_key_id);
    println!("signature       {}", hex::encode(row.signature));
    println!("payload         {}", row.payload);
    println!();

    let entries = repo.db().get_tree(&row.root_tree)?;
    println!("root tree:");
    for e in entries {
        let marker = match e.kind {
            TreeEntryKind::Tree => "tree/",
            TreeEntryKind::Blob => "blob ",
        };
        println!("  {marker} {:o} {}  {}", e.mode, e.target, e.name);
    }
    Ok(())
}

pub fn fsck(args: FsckArgs) -> Result<()> {
    let garden = resolve_existing(args.garden)?;

    let socket = softfig_ipc::runtime_socket_path();
    if let Some(reply) = try_daemon_call(&socket, op::FSCK, serde_json::Value::Null)
        .map_err(|e| anyhow!("daemon: {e}"))?
    {
        let r: FsckReply = serde_json::from_value(reply)?;
        println!(
            "checked: {} commits, {} trees, {} objects",
            r.commits_checked, r.trees_checked, r.objects_checked
        );
        if !r.orphan_objects.is_empty() {
            println!(
                "orphan objects ({} — gc would collect):",
                r.orphan_objects.len()
            );
            for h in &r.orphan_objects {
                println!("  {h}");
            }
        }
        if r.problems.is_empty() {
            println!("ok");
            return Ok(());
        } else {
            println!("problems ({}):", r.problems.len());
            for p in &r.problems {
                println!("  {p}");
            }
            return Err(anyhow!("fsck found {} problem(s)", r.problems.len()));
        }
    }

    forbid_direct_mode_when_migrated(&garden)?;
    let repo = Repo::open(&garden)?;
    let report: FsckReport = run_fsck(repo.db(), repo.objects())?;
    println!(
        "checked: {} commits, {} trees, {} objects",
        report.commits_checked, report.trees_checked, report.objects_checked
    );
    if !report.orphan_objects.is_empty() {
        println!(
            "orphan objects ({} — gc would collect):",
            report.orphan_objects.len()
        );
        for h in &report.orphan_objects {
            println!("  {h}");
        }
    }
    if report.problems.is_empty() {
        println!("ok");
    } else {
        println!("problems ({}):", report.problems.len());
        for p in &report.problems {
            println!("  {p}");
        }
        return Err(anyhow!("fsck found {} problem(s)", report.problems.len()));
    }
    Ok(())
}

// ---- helpers ----

fn resolve_for_init(garden: Option<PathBuf>) -> Result<PathBuf> {
    Ok(match garden {
        Some(p) => p,
        None => std::env::current_dir().context("could not read $PWD")?,
    })
}

fn resolve_existing(garden: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = garden {
        return Ok(p);
    }
    let here = std::env::current_dir().context("could not read $PWD")?;
    discover_garden(&here)
        .ok_or_else(|| anyhow!("no .softfig/ found in {} or any parent", here.display()))
}

/// M2a: migrated gardens forbid direct-mode CLI access — the daemon is
/// the sole writer. This is checked AFTER the daemon-bridge fast path
/// (so a reachable daemon serves the request normally); the error
/// fires only on the direct-mode fallback.
fn forbid_direct_mode_when_migrated(garden: &Path) -> Result<()> {
    let toml_path = garden.join(".softfig").join("keeper.toml");
    if !toml_path.exists() {
        return Ok(());
    }
    let raw = std::fs::read_to_string(&toml_path)
        .with_context(|| format!("read {}", toml_path.display()))?;
    #[derive(serde::Deserialize)]
    struct Cfg {
        state_root: Option<PathBuf>,
    }
    let cfg: Cfg =
        toml::from_str(&raw).with_context(|| format!("parse {}", toml_path.display()))?;
    if cfg.state_root.is_some() {
        return Err(anyhow!(
            "this garden is migrated to FUSE — start the daemon (`softfig daemon start`) first"
        ));
    }
    Ok(())
}

fn parse_intent_name(s: &str) -> std::result::Result<String, String> {
    if KNOWN_INTENTS.contains(&s) {
        Ok(s.to_string())
    } else {
        Err(format!(
            "unknown intent {s:?}; expected one of: {}",
            KNOWN_INTENTS.join(", ")
        ))
    }
}

fn build_payload(args: &CommitArgs) -> Result<serde_json::Value> {
    if let Some(raw) = &args.payload_json {
        let v: serde_json::Value =
            serde_json::from_str(raw).context("--payload-json must be valid JSON")?;
        if !v.is_object() {
            return Err(anyhow!("--payload-json must be a JSON object"));
        }
        return Ok(v);
    }

    let mut obj = serde_json::Map::new();
    if let Some(msg) = &args.message {
        obj.insert(
            "summary".to_string(),
            serde_json::Value::String(msg.clone()),
        );
    }
    if !args.files.is_empty() {
        obj.insert(
            "files".to_string(),
            serde_json::Value::Array(
                args.files
                    .iter()
                    .map(|s| serde_json::Value::String(s.clone()))
                    .collect(),
            ),
        );
    }
    for kv in &args.kvs {
        let (k, v) = kv
            .split_once('=')
            .ok_or_else(|| anyhow!("--kv {kv:?} must be key=value"))?;
        obj.insert(k.to_string(), serde_json::Value::String(v.to_string()));
    }
    Ok(serde_json::Value::Object(obj))
}

fn prompt_passphrase(prompt: &str) -> Result<String> {
    rpassword::prompt_password(prompt).context("could not read passphrase from tty")
}

fn iso8601(unix: i64) -> String {
    // Tiny formatter — avoid pulling chrono/time just for printing.
    let days = unix.div_euclid(86_400);
    let secs_in_day = unix.rem_euclid(86_400);
    let hh = secs_in_day / 3600;
    let mm = (secs_in_day % 3600) / 60;
    let ss = secs_in_day % 60;
    let (y, mo, d) = ymd_from_days(days);
    format!("{y:04}-{mo:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Convert days-since-1970-01-01 to a (year, month, day) triple. Handles
/// negatives (pre-epoch timestamps) cleanly via Howard Hinnant's algorithm.
fn ymd_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn short_summary(payload_canon: &str) -> String {
    let v: serde_json::Value = match serde_json::from_str(payload_canon) {
        Ok(v) => v,
        Err(_) => return String::new(),
    };
    if let Some(s) = v.get("summary").and_then(|v| v.as_str()) {
        return s.to_string();
    }
    if let Some(s) = v.get("slug").and_then(|v| v.as_str()) {
        return s.to_string();
    }
    if let Some(arr) = v.get("files").and_then(|v| v.as_array()) {
        let names: Vec<String> = arr
            .iter()
            .filter_map(|s| s.as_str().map(String::from))
            .take(3)
            .collect();
        let extra = if arr.len() > 3 {
            format!(" (+{} more)", arr.len() - 3)
        } else {
            String::new()
        };
        return format!("[{}]{}", names.join(", "), extra);
    }
    String::new()
}
