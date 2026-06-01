//! Hardcoded garden conventions (M3a Pick D): path templates, header +
//! stub templates, and validators matching the OG garden's
//! `meta/conventions.md` + `meta/reserved-filenames.md`. User-customizable
//! schema (`.softfig/conventions.toml`) is a later iteration — keeping the
//! schema here as Rust constants reuses the OG conventions verbatim and
//! keeps M3a tight.

use std::time::{SystemTime, UNIX_EPOCH};

use softfig_ipc::ErrorKind;

pub const SLUG_MAX: usize = 64;
pub const PROJECT_NAME_MAX: usize = 64;

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

/// The four reserved-name stubs every project dir carries.
pub const PROJECT_STUBS: [&str; 4] = ["CLAUDE.md", "instructions.md", "notes.md", "refs.md"];

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

pub fn project_notes_md(name: &str, date_hyphen: &str) -> String {
    format!(
        "# notes\n\n> Last reviewed: {date_hyphen}\n\n\
         Running decision log + non-obvious learnings for `{name}`.\n"
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
}
