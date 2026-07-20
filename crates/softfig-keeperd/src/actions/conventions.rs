//! Hardcoded garden conventions (M3a Pick D): path templates, header +
//! stub templates, and validators matching the OG garden's
//! `meta/conventions.md` + `meta/reserved-filenames.md`. User-customizable
//! schema (`.softfig/conventions.toml`) is a later iteration — keeping the
//! schema here as Rust constants reuses the OG conventions verbatim and
//! keeps M3a tight.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use softfig_ipc::ErrorKind;

pub const SLUG_MAX: usize = 64;
pub const PROJECT_NAME_MAX: usize = 64;

/// Reserved filename for an accretive folder's daemon-owned high-water
/// mark. Never read or written by Claude — see `meta/spec-small-files.md`.
pub const SEQ_FILE: &str = ".seq";

/// Reserved-name folders that hold numbered single-doc entries (Slice 1 of
/// the small-files redesign; `code-reviews` added by task 020). The basename
/// of a `revise_note` `dir` must be one of these; the add verbs gate on the
/// genre subsets below.
pub const ACCRETIVE_FOLDERS: [&str; 3] = ["notes", "troubleshooting", "code-reviews"];

/// The note-genre accretive folders `add_note` may write into. A code review
/// is a distinct genre — `add_code_review` owns `code-reviews/` — so the two
/// add verbs stay out of each other's folders even though `revise_note`,
/// numbering, indexes, and backlinks treat all of [`ACCRETIVE_FOLDERS`]
/// uniformly.
pub const NOTE_FOLDERS: [&str; 2] = ["notes", "troubleshooting"];

/// The code-review-genre accretive folders `add_code_review` may write into
/// (task 020). Primary home `projects/<project>/code-reviews/`; the name is
/// reserved garden-wide, so any concept dir may hold one.
pub const CODE_REVIEW_FOLDERS: [&str; 1] = ["code-reviews"];

// ---- path templates ---------------------------------------------------

pub fn decision_path(slug: &str) -> String {
    format!("journal/decisions/decision-{slug}.md")
}

pub fn incident_path(date_compact: &str, slug: &str) -> String {
    format!("journal/incidents/incident-{date_compact}-{slug}.md")
}

pub fn project_dir(name: &str) -> String {
    format!("projects/{name}")
}

/// The monolithic reserved-name stubs every project dir carries. The
/// fourth accretive doc, `notes`, is now a numbered-note **folder** (seeded
/// as `notes/.seq`), not a `notes.md` monolith — see [`is_accretive_dir`].
pub const PROJECT_STUBS: [&str; 3] = ["CLAUDE.md", "instructions.md", "refs.md"];

/// Whether `dir_rel`'s basename names an accretive folder. `revise_note`
/// and the shared numbering/index/backlink machinery operate on all of
/// these; the add verbs gate on their genre subset via [`dir_basename_in`].
pub fn is_accretive_dir(dir_rel: &str) -> bool {
    dir_basename_in(dir_rel, &ACCRETIVE_FOLDERS)
}

/// Whether `dir_rel`'s basename is one of `allowed` — the genre gate the
/// add verbs apply on top of the accretive-folder machinery.
pub fn dir_basename_in(dir_rel: &str, allowed: &[&str]) -> bool {
    Path::new(dir_rel)
        .file_name()
        .and_then(|s| s.to_str())
        .map(|name| allowed.contains(&name))
        .unwrap_or(false)
}

/// `NNN-slug.md` — 3-digit zero-padded number + the terse slug address.
pub fn note_filename(number: u32, slug: &str) -> String {
    format!("{number:03}-{slug}.md")
}

// ---- header + body stamping -------------------------------------------

/// `# decision: <title>` + `Date:` header, body below. Per the decision
/// file's body-stamping resolution the daemon always stamps on top — it
/// does not parse or trust caller-supplied markdown headers.
pub fn decision_doc(title: &str, date_hyphen: &str, body: &str) -> String {
    format!(
        "# decision: {title}\n\nDate: {date_hyphen}\n\n{}\n",
        body.trim_end_matches('\n')
    )
}

/// `# <YYYY-MM-DD> — <summary>` header, body below.
pub fn incident_doc(date_hyphen: &str, summary: &str, body: &str) -> String {
    format!(
        "# {date_hyphen} — {summary}\n\n{}\n",
        body.trim_end_matches('\n')
    )
}

/// `# <title>` + `> Last reviewed:` header, body below. The creation order
/// is carried by the filename number, so there's no created-date line —
/// only the reviewed stamp, which `revise_note`/`set_reviewed` bump.
pub fn note_doc(title: &str, date_hyphen: &str, body: &str) -> String {
    format!(
        "# {title}\n\n> Last reviewed: {date_hyphen}\n\n{}\n",
        body.trim_end_matches('\n')
    )
}

// ---- note field parsers (shared by add_note + the index builder) ------

/// Parse the `NNN` from a `NNN-<slug>.md` filename (exactly three leading
/// digits then a dash). Anything else (incl. `.seq`, `01-x.md`, `abc-x.md`)
/// is `None`.
pub fn parse_note_number(name: &str) -> Option<u32> {
    let bytes = name.as_bytes();
    if name.ends_with(".md")
        && bytes.len() >= 5
        && bytes[3] == b'-'
        && bytes[..3].iter().all(u8::is_ascii_digit)
    {
        name[..3].parse().ok()
    } else {
        None
    }
}

/// The first `# <title>` heading text, trimmed. `None` if the doc has no
/// top-level heading.
pub fn note_title(content: &str) -> Option<String> {
    content
        .lines()
        .find_map(|line| line.strip_prefix("# ").map(|rest| rest.trim().to_string()))
}

/// The date on the first `Last reviewed:` line (optionally `> `-quoted /
/// indented), trimmed. `None` if there's no such line. A prose mention
/// ("see Last reviewed: …") is skipped — only blanks / quote markers may
/// precede the label.
pub fn note_reviewed(content: &str) -> Option<String> {
    content.lines().find_map(|line| {
        let stripped = line.trim_start_matches([' ', '\t', '>']);
        stripped
            .strip_prefix("Last reviewed:")
            .map(|date| date.trim().to_string())
    })
}

/// The `<slug>` of a `NNN-<slug>.md` filename, used only as a title
/// fallback. Falls back to `"note"` for a malformed name.
pub fn slug_from_note_name(name: &str) -> String {
    name.strip_suffix(".md")
        .and_then(|stem| stem.split_once('-').map(|(_, slug)| slug.to_string()))
        .unwrap_or_else(|| "note".to_string())
}

// ---- project stub templates -------------------------------------------

/// `CLAUDE.md` is the routing doc — no `Last reviewed:` line (it's not a
/// snapshot of state). The repo sentence is inlined only when a repo_path
/// is supplied.
pub fn project_claude_md(name: &str, repo_path: Option<&str>, summary: Option<&str>) -> String {
    let repo_line = match repo_path {
        Some(p) => format!(" The actual code lives at `{p}`."),
        None => String::new(),
    };
    let summary_para = match summary {
        Some(s) => format!("\n\n{s}"),
        None => String::new(),
    };
    format!(
        "# projects/{name}/\n\n\
         Garden view of `{name}`.{repo_line} This dir holds the framing — how the \
         project fits the system, what state it's in, what comes next — not the code \
         itself.{summary_para}\n\n\
         ## How to behave here\n\n\
         - Code-level questions (build, architecture, FFI) → the real repo's `CLAUDE.md` \
         (linked from `refs.md`); that's authoritative for code.\n\
         - System-level questions (how it fits the desktop/services, why it exists here, \
         what comes next) → this dir.\n\
         - Don't duplicate code-level detail from the repo; point at it.\n"
    )
}

pub fn project_instructions_md(name: &str, date_hyphen: &str) -> String {
    format!(
        "# instructions\n\n> Last reviewed: {date_hyphen}\n\n\
         Milestone + status tracking for `{name}`. Update at each milestone boundary.\n"
    )
}

pub fn project_refs_md(name: &str, date_hyphen: &str, repo_path: Option<&str>) -> String {
    let repo_line = match repo_path {
        Some(p) => format!("- Real repo: `{p}` — its `CLAUDE.md` is authoritative for code.\n"),
        None => String::new(),
    };
    format!(
        "# refs\n\n> Last reviewed: {date_hyphen}\n\n\
         Cross-refs for `{name}`.\n\n## Cross-refs\n\n{repo_line}"
    )
}

// ---- validators -------------------------------------------------------

/// `[a-z0-9-]+`, length 1–64. Same constraint as the M2c `<vault id>`
/// charset.
pub fn validate_slug(slug: &str) -> Result<(), (ErrorKind, String)> {
    if slug.is_empty() || slug.len() > SLUG_MAX {
        return Err((
            ErrorKind::InvalidSlug,
            format!("slug must be 1–{SLUG_MAX} bytes, got {}", slug.len()),
        ));
    }
    if !slug
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err((
            ErrorKind::InvalidSlug,
            format!("slug {slug:?}: charset must be [a-z0-9-]"),
        ));
    }
    Ok(())
}

/// Derive a valid `[a-z0-9-]+` slug from free text: lowercase, runs of
/// non-alphanumerics collapse to a single `-`, leading/trailing dashes
/// trimmed, truncated to [`SLUG_MAX`]. Empty input falls back to `"note"`.
/// Used by the migration splitter to address sections by their heading.
pub fn slugify(text: &str) -> String {
    let mut out = String::new();
    let mut pending_dash = false;
    for ch in text.chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            if pending_dash && !out.is_empty() {
                out.push('-');
            }
            pending_dash = false;
            out.push(c);
        } else {
            pending_dash = true;
        }
    }
    if out.len() > SLUG_MAX {
        out.truncate(SLUG_MAX);
        while out.ends_with('-') {
            out.pop();
        }
    }
    if out.is_empty() {
        out.push_str("note");
    }
    out
}

/// Reduce a free-form name to a single, safe filename component for
/// interpolation into an **in-tree** path. Any character outside
/// `[A-Za-z0-9._-]` (notably `/`) becomes `_`, so the result is exactly one
/// path component with no separators; any run of `.` collapses to a single
/// `.`, so the name can never form a `..` parent-traversal component even glued
/// into surrounding text. Empty (or fully-stripped) input yields `_`.
///
/// Pure + deterministic — the same input bytes always map to the same output —
/// so two nodes independently sanitizing the same peer device name derive the
/// identical path (the conflict-sidecar resolver depends on this: LWW
/// convergence must survive the guard). Unlike [`slugify`] it preserves case
/// and the `[._]` set, keeping the human-visible sidecar name close to the real
/// device name.
pub(crate) fn sanitize_name_component(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_dot = false;
    for ch in name.chars() {
        let c = if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
            ch
        } else {
            '_'
        };
        if c == '.' {
            // Collapse a run of dots to one, killing any `..` traversal.
            if prev_dot {
                continue;
            }
            prev_dot = true;
        } else {
            prev_dot = false;
        }
        out.push(c);
    }
    if out.is_empty() {
        out.push('_');
    }
    out
}

/// `[a-z0-9]([a-z0-9-]*[a-z0-9])?`, length 1–64 (no leading/trailing dash).
pub fn validate_project_name(name: &str) -> Result<(), (ErrorKind, String)> {
    if name.is_empty() || name.len() > PROJECT_NAME_MAX {
        return Err((
            ErrorKind::InvalidProjectName,
            format!("project name must be 1–{PROJECT_NAME_MAX} bytes, got {}", name.len()),
        ));
    }
    let bytes = name.as_bytes();
    if !bytes
        .iter()
        .all(|&b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err((
            ErrorKind::InvalidProjectName,
            format!("project name {name:?}: charset must be [a-z0-9-]"),
        ));
    }
    if bytes[0] == b'-' || bytes[bytes.len() - 1] == b'-' {
        return Err((
            ErrorKind::InvalidProjectName,
            format!("project name {name:?}: no leading/trailing dash"),
        ));
    }
    Ok(())
}

/// `YYYYMMDD` — exactly 8 ASCII digits with a sane month/day range.
pub fn validate_incident_date(date: &str) -> Result<(), (ErrorKind, String)> {
    if date.len() != 8 || !date.bytes().all(|b| b.is_ascii_digit()) {
        return Err((
            ErrorKind::BadArgs,
            format!("date {date:?}: must be YYYYMMDD (8 digits)"),
        ));
    }
    let month: u32 = date[4..6].parse().unwrap_or(0);
    let day: u32 = date[6..8].parse().unwrap_or(0);
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err((
            ErrorKind::BadArgs,
            format!("date {date:?}: month/day out of range"),
        ));
    }
    Ok(())
}

/// Reformat `YYYYMMDD` → `YYYY-MM-DD`. Caller has already validated.
pub fn compact_to_hyphen(date_compact: &str) -> String {
    format!(
        "{}-{}-{}",
        &date_compact[0..4],
        &date_compact[4..6],
        &date_compact[6..8]
    )
}

// ---- date helpers (no chrono dep; civil-from-days, Howard Hinnant) ----

fn today_civil() -> (i64, u32, u32) {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    civil_from_days(secs.div_euclid(86_400))
}

/// Convert a count of days since 1970-01-01 to (year, month [1-12],
/// day [1-31]) in the proleptic Gregorian calendar.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 }.div_euclid(146_097);
    let doe = z - era * 146_097; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0,399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0,365]
    let mp = (5 * doy + 2) / 153; // [0,11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1,31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1,12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

pub fn today_compact() -> String {
    let (y, m, d) = today_civil();
    format!("{y:04}{m:02}{d:02}")
}

pub fn today_hyphen() -> String {
    let (y, m, d) = today_civil();
    format!("{y:04}-{m:02}-{d:02}")
}

/// The current UTC wall-clock as an RFC 3339 timestamp
/// (`YYYY-MM-DDTHH:MM:SSZ`). Used to stamp coordination-bus messages; purely
/// informational (bus order is by message number, never by `ts`).
pub fn now_rfc3339() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    let sod = secs.rem_euclid(86_400);
    let (hh, mm, ss) = (sod / 3600, (sod % 3600) / 60, sod % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// The current Unix wall-clock in whole seconds. Feeds the thrash detector's
/// window math; the detector itself takes an injected `now` so its tests never
/// touch the real clock (this is only called on the live edit path).
pub fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_from_days_known_points() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(31), (1970, 2, 1));
        assert_eq!(civil_from_days(365), (1971, 1, 1));
        assert_eq!(civil_from_days(10_957), (2000, 1, 1));
        // 2000 was a leap year: day 10957 + 31 (Jan) + 29 (Feb) = 11017 → Mar 1.
        assert_eq!(civil_from_days(11_017), (2000, 3, 1));
    }

    #[test]
    fn today_formats_are_well_formed() {
        let compact = today_compact();
        assert_eq!(compact.len(), 8);
        assert!(compact.bytes().all(|b| b.is_ascii_digit()));
        assert!(validate_incident_date(&compact).is_ok());
        let hyphen = today_hyphen();
        assert_eq!(hyphen.len(), 10);
        assert_eq!(compact_to_hyphen(&compact), hyphen);
    }

    #[test]
    fn slug_rules() {
        assert!(validate_slug("ok-slug-123").is_ok());
        assert!(validate_slug("").is_err());
        assert!(validate_slug("Bad_Slug").is_err());
        assert!(validate_slug("has space").is_err());
        assert!(validate_slug(&"a".repeat(65)).is_err());
    }

    #[test]
    fn project_name_rules() {
        assert!(validate_project_name("cool-proj9").is_ok());
        assert!(validate_project_name("a").is_ok());
        assert!(validate_project_name("-lead").is_err());
        assert!(validate_project_name("trail-").is_err());
        assert!(validate_project_name("Caps").is_err());
        assert!(validate_project_name("").is_err());
    }

    #[test]
    fn incident_date_rules() {
        assert!(validate_incident_date("20260530").is_ok());
        assert!(validate_incident_date("2026-05-30").is_err());
        assert!(validate_incident_date("20261301").is_err());
        assert!(validate_incident_date("baddate1").is_err());
    }

    #[test]
    fn accretive_dir_rules() {
        assert!(is_accretive_dir("services/waydroid/notes"));
        assert!(is_accretive_dir("notes"));
        assert!(is_accretive_dir("input/controllers/troubleshooting"));
        assert!(is_accretive_dir("projects/demo/code-reviews"));
        assert!(!is_accretive_dir("services/waydroid"));
        assert!(!is_accretive_dir("notes.md"));
        assert!(!is_accretive_dir("journal/decisions"));
        assert!(!is_accretive_dir(""));
    }

    /// The genre subsets partition the accretive set — every genre folder is
    /// accretive, and the two add-verb gates never overlap.
    #[test]
    fn genre_folders_partition_accretive_set() {
        for name in NOTE_FOLDERS.iter().chain(CODE_REVIEW_FOLDERS.iter()) {
            assert!(ACCRETIVE_FOLDERS.contains(name), "{name} not accretive");
        }
        assert_eq!(
            NOTE_FOLDERS.len() + CODE_REVIEW_FOLDERS.len(),
            ACCRETIVE_FOLDERS.len()
        );
        assert!(!NOTE_FOLDERS.iter().any(|n| CODE_REVIEW_FOLDERS.contains(n)));
    }

    #[test]
    fn note_filename_zero_pads() {
        assert_eq!(note_filename(1, "container-networking"), "001-container-networking.md");
        assert_eq!(note_filename(42, "gpu"), "042-gpu.md");
        assert_eq!(note_filename(123, "x"), "123-x.md");
    }

    #[test]
    fn note_doc_shape() {
        let doc = note_doc("GPU passthrough", "2026-06-10", "It needs the venus driver.\n\n");
        assert_eq!(
            doc,
            "# GPU passthrough\n\n> Last reviewed: 2026-06-10\n\nIt needs the venus driver.\n"
        );
    }

    #[test]
    fn parse_note_number_accepts_notes_only() {
        assert_eq!(parse_note_number("001-container.md"), Some(1));
        assert_eq!(parse_note_number("042-gpu-passthrough.md"), Some(42));
        assert_eq!(parse_note_number(".seq"), None);
        assert_eq!(parse_note_number("01-short.md"), None);
        assert_eq!(parse_note_number("001-x.txt"), None);
        assert_eq!(parse_note_number("abc-x.md"), None);
        assert_eq!(parse_note_number("001x.md"), None);
    }

    #[test]
    fn note_title_reads_first_heading() {
        let doc = "# GPU passthrough\n\n> Last reviewed: 2026-06-10\n\nbody\n";
        assert_eq!(note_title(doc).as_deref(), Some("GPU passthrough"));
        assert_eq!(note_title("no heading here\n"), None);
    }

    #[test]
    fn note_reviewed_reads_quoted_and_bare() {
        let doc = "# N\n\n> Last reviewed: 2026-06-10\n\nbody\n";
        assert_eq!(note_reviewed(doc).as_deref(), Some("2026-06-10"));
        assert_eq!(note_reviewed("Last reviewed: 2020-01-01\n").as_deref(), Some("2020-01-01"));
        assert_eq!(note_reviewed("# N\n\nno stamp\n"), None);
        // A prose mention is not a stamp line.
        assert_eq!(note_reviewed("see Last reviewed: foo\n"), None);
    }

    #[test]
    fn slug_from_note_name_strips_number_and_ext() {
        assert_eq!(slug_from_note_name("004-adb-port.md"), "adb-port");
        assert_eq!(slug_from_note_name("001-x.md"), "x");
        assert_eq!(slug_from_note_name("garbled"), "note");
    }

    #[test]
    fn sanitize_name_component_yields_one_safe_component() {
        // Common device names round-trip unchanged (case + `[._-]` preserved).
        assert_eq!(sanitize_name_component("peerbox"), "peerbox");
        assert_eq!(sanitize_name_component("laptop-01_v2.3"), "laptop-01_v2.3");
        // Separators and traversal are neutralized to one safe component.
        assert_eq!(sanitize_name_component("a/b"), "a_b");
        assert_eq!(sanitize_name_component(".."), ".");
        assert_eq!(sanitize_name_component("../escape"), "._escape");
        assert_eq!(sanitize_name_component("x/../../y"), "x_._._y");
        assert_eq!(sanitize_name_component(""), "_");
        // Invariant: never a separator, never a bare `..` run, never empty.
        for s in ["a/b", "../escape", "x/../../y", "..", "///", "a..b..c", "dev name!"] {
            let out = sanitize_name_component(s);
            assert!(!out.contains('/'), "{s:?} -> {out:?} kept a separator");
            assert!(!out.contains(".."), "{s:?} -> {out:?} kept a '..' run");
            assert!(!out.is_empty(), "{s:?} -> empty");
        }
    }

    #[test]
    fn slugify_rules() {
        assert_eq!(slugify("GPU passthrough"), "gpu-passthrough");
        assert_eq!(slugify("ADB: port collision!"), "adb-port-collision");
        assert_eq!(slugify("  leading / trailing  "), "leading-trailing");
        assert_eq!(slugify("---"), "note");
        assert_eq!(slugify(""), "note");
        assert!(slugify(&"x ".repeat(80)).len() <= SLUG_MAX);
        // Slugify output is always a valid slug.
        assert!(validate_slug(&slugify("Some Heading (v2)")).is_ok());
    }
}
