//! The growlight **baton** — the curated handoff a loop session writes at its
//! boundary — and its terminal-status vocabulary.
//!
//! Two readers consume a baton's `status:` field to decide whether to keep the
//! loop going:
//!
//! - the single-agent `--auto` orchestrator (`softfig-cli`'s `cmd_growlight`),
//!   which stops the one-shot session on a terminal status; and
//! - the **fleet** supervisor (`softfig-growlightd`), which retires/parks/re-rolls
//!   the member that wrote it.
//!
//! Both crates depend on `softfig-ipc`, so the parse + the classification live
//! here as the ONE shared implementation — there is exactly one status vocabulary
//! and one frontmatter parser, never a re-derived copy that can drift
//! (`feedback_no_patchwork_fixes`). See
//! `journal/decisions/decision-growlight-fleet-loop-spin.md`: the fleet missing
//! this read was the empty-queue spin.

/// Whether `status` is a **within-item** continue — the agent handed off
/// mid-part and the SAME part is still its work (`IN_PROGRESS`). This is the only
/// status that re-rolls the same part with the curated baton carried forward.
/// `ITEM_COMPLETE` / `ITEM_DEFERRED` are NOT within-item continues — they are
/// item *boundaries* ([`BatonDisposition::ItemBoundary`]): the part is
/// finished/deferred, so the fleet releases the member's slot and the
/// orchestrator claims its next part (a member never self-pulls). The
/// single-agent `--auto` driver, which has no orchestrator, keeps driving on both
/// a continue and a boundary (it self-pulls the next item) — see
/// [`BatonDisposition`].
pub fn is_continue_status(status: &str) -> bool {
    matches!(status, "IN_PROGRESS")
}

/// How a baton's terminal-status field classifies, independent of the budget
/// governor and spin guard each reader layers on top. This is the shared
/// "continue / boundary / terminal" decision both the single-agent driver and the
/// fleet supervisor key off. Each reader maps it to its own lifecycle: the
/// `--auto` driver folds `QueueEmpty`/`Stuck` into a single terminal stop and
/// keeps driving on both `Continue` and `ItemBoundary` (it self-pulls the next
/// item), while the fleet tells them apart — `Continue` re-rolls the SAME part,
/// `ItemBoundary` releases the slot so the orchestrator claims the next part (the
/// fleet-member-model fix), `QueueEmpty` retires to idle, a rate-limit parks, and
/// a human-block/stuck parks pending a human.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatonDisposition {
    /// `IN_PROGRESS` — a **within-item** handoff: the agent paused mid-part and
    /// the same part is still its work. The fleet re-rolls the SAME part with the
    /// member's curated baton carried forward (no re-claim, no re-seed); the
    /// single-agent driver keeps driving.
    Continue,
    /// `ITEM_COMPLETE` / `ITEM_DEFERRED` — an **item boundary**: the agent finished
    /// or deferred its part (it already wrote `set_item_status`), so its current
    /// part is done. The fleet **releases the member's slot** (drops it from the
    /// supervisor) and the orchestrator claims + seeds its NEXT part through the
    /// same double-assignment-safe handshake a fresh start uses — the member never
    /// self-pulls. The single-agent `--auto` driver, which has no orchestrator,
    /// treats this exactly like [`Continue`] and self-pulls the next item.
    ItemBoundary,
    /// `QUEUE_EMPTY` — the queue is drained. Clean: the single-agent loop stops;
    /// the fleet retires the member to idle (no alert). The daemon stays resident
    /// and re-starts a member when new queued work appears.
    QueueEmpty,
    /// `HALTED_RATE_LIMIT` — the agent halted on a rate window; resume at its
    /// reset (a governor pause / a parked member), never a hard stop.
    RateLimited,
    /// `BLOCKED_ON_HUMAN` — a hard block needing a human decision; surfaced
    /// loudly, never worked around or fabricated.
    BlockedOnHuman,
    /// An agent-written `STUCK`, an unrecognized status, or a missing one — the
    /// loop can't safely continue. Carries the raw status string for the
    /// log/alert.
    Stuck(String),
}

/// Classify a baton `status:` field. A missing status (`None`) is the `"UNKNOWN"`
/// sentinel → [`BatonDisposition::Stuck`] (can't safely continue on no signal).
/// Callers that have only the status string (the fleet supervisor) use this;
/// callers with a full baton use [`BatonView::classify`].
pub fn classify_status(status: Option<&str>) -> BatonDisposition {
    match status.unwrap_or("UNKNOWN") {
        "HALTED_RATE_LIMIT" => BatonDisposition::RateLimited,
        "BLOCKED_ON_HUMAN" => BatonDisposition::BlockedOnHuman,
        "QUEUE_EMPTY" => BatonDisposition::QueueEmpty,
        "ITEM_COMPLETE" | "ITEM_DEFERRED" => BatonDisposition::ItemBoundary,
        s if is_continue_status(s) => BatonDisposition::Continue,
        s => BatonDisposition::Stuck(s.to_string()),
    }
}

/// Every `status:` value a loop session may legitimately write in its handoff
/// baton, in lifecycle order — the within-item continue, the two item boundaries,
/// then the three stops/parks. This is the ONE source of truth for any doc,
/// prompt, or seed that *enumerates* the vocabulary (the growlightd seed baton's
/// NEXT ACTION builds its list from here), so the enumeration can never drift from
/// [`classify_status`] — every entry is a status `classify_status` recognizes (the
/// round-trip is asserted in the tests). `STUCK` is the *named* member of the
/// catch-all [`BatonDisposition::Stuck`] bucket; an unrecognized status also
/// classifies as `Stuck` but is not part of the vocabulary an agent is told to
/// write.
pub const STATUS_VOCABULARY: &[&str] = &[
    "IN_PROGRESS",
    "ITEM_COMPLETE",
    "ITEM_DEFERRED",
    "QUEUE_EMPTY",
    "HALTED_RATE_LIMIT",
    "BLOCKED_ON_HUMAN",
    "STUCK",
];

/// The fields a reader pulls from the runtime baton each iteration: the
/// terminal-status signal plus the progress signal (item / iteration / NEXT
/// ACTION) the single-agent spin guard keys off.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BatonView {
    /// The frontmatter `status:` field, if present.
    pub status: Option<String>,
    /// The frontmatter `item:` field (the active backlog item), if present.
    pub item: Option<String>,
    /// The frontmatter `slice:` field — which ordered slice of `item` is being
    /// worked, for a milestone. `None` for a standalone task (and for a milestone
    /// baton that names none). A reader resolving the ACTIVE slice's doc — the
    /// launcher, reading the model that slice declares for itself — needs this
    /// alongside `item`; it is parsed here rather than re-derived, like every
    /// other frontmatter field.
    pub slice: Option<String>,
    /// The frontmatter `iteration:` counter, if a valid integer.
    pub iteration: Option<u64>,
    /// The `# NEXT ACTION` section body, if present.
    pub next_action: Option<String>,
}

impl BatonView {
    /// Classify this baton's status — the shared continue/terminal decision.
    pub fn classify(&self) -> BatonDisposition {
        classify_status(self.status.as_deref())
    }
}

/// Parse the runtime baton: `status` / `item` / `slice` / `iteration` from the
/// YAML frontmatter and the `# NEXT ACTION` section body. Pure; a reader re-reads
/// this after every iteration to decide whether to keep driving.
pub fn parse_baton(baton: &str) -> BatonView {
    let mut status = None;
    let mut item = None;
    let mut slice = None;
    let mut iteration = None;

    let mut lines = baton.lines();
    // Frontmatter opens with a `---` fence.
    if lines.next().map(str::trim) == Some("---") {
        for line in lines.by_ref() {
            let line = line.trim();
            if line == "---" {
                break;
            }
            if let Some(v) = line.strip_prefix("status:") {
                let v = v.trim();
                if !v.is_empty() {
                    status = Some(v.to_string());
                }
            } else if let Some(v) = line.strip_prefix("item:") {
                let v = v.trim();
                if !v.is_empty() && v != "null" {
                    item = Some(v.to_string());
                }
            } else if let Some(v) = line.strip_prefix("slice:") {
                let v = v.trim();
                if !v.is_empty() && v != "null" {
                    slice = Some(v.to_string());
                }
            } else if let Some(v) = line.strip_prefix("iteration:") {
                iteration = v.trim().parse::<u64>().ok();
            }
        }
    }

    BatonView {
        status,
        item,
        slice,
        iteration,
        next_action: extract_section(baton, "# NEXT ACTION"),
    }
}

/// Extract a top-level (`# `) section body from the baton — everything between
/// `heading` and the next `# ` heading — trimmed. `None` if absent or empty.
fn extract_section(baton: &str, heading: &str) -> Option<String> {
    let mut body: Vec<&str> = Vec::new();
    let mut in_section = false;
    for line in baton.lines() {
        if in_section {
            if line.starts_with("# ") {
                break;
            }
            body.push(line);
        } else if line.trim() == heading {
            in_section = true;
        }
    }
    let joined = body.join("\n");
    let trimmed = joined.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_baton_reads_frontmatter_and_the_next_action_section() {
        let baton = "---\nloop: g\nstatus: QUEUE_EMPTY\nitem: full-auto-orchestrator\n\
                     item_type: milestone\niteration: 4\n---\n# NEXT ACTION\ndo the thing\n\
                     more detail\n\n# FINISH CRITERIA\nstatus: not-this\n";
        let v = parse_baton(baton);
        assert_eq!(v.status.as_deref(), Some("QUEUE_EMPTY"));
        // `item:` must not be confused with `item_type:`.
        assert_eq!(v.item.as_deref(), Some("full-auto-orchestrator"));
        assert_eq!(v.iteration, Some(4));
        // NEXT ACTION stops at the next `# ` heading and ignores the body's
        // `status:` line.
        assert_eq!(v.next_action.as_deref(), Some("do the thing\nmore detail"));

        // No frontmatter fence → no fields.
        let none = parse_baton("status: nope\n");
        assert!(none.status.is_none());
        assert!(none.next_action.is_none());

        // `item: null` is read as absent, not the literal string.
        let nullish = parse_baton("---\nstatus: IN_PROGRESS\nitem: null\n---\n# NEXT ACTION\nx\n");
        assert!(nullish.item.is_none());
        assert_eq!(nullish.status.as_deref(), Some("IN_PROGRESS"));
        assert_eq!(nullish.next_action.as_deref(), Some("x"));
    }

    #[test]
    fn parse_baton_reads_the_active_slice() {
        // The launcher resolves the active slice's doc from `item` + `slice`, so
        // the slice must survive the parse verbatim (padded or not).
        let v = parse_baton("---\nstatus: IN_PROGRESS\nitem: astro-view\nslice: 006\n---\n");
        assert_eq!(v.item.as_deref(), Some("astro-view"));
        assert_eq!(v.slice.as_deref(), Some("006"));
        assert_eq!(parse_baton("---\nslice: 6\n---\n").slice.as_deref(), Some("6"));

        // A task baton (or a milestone that hasn't named one) carries no slice —
        // `null` and absent both read as None, never the literal string.
        assert!(parse_baton("---\nitem: 047\nslice: null\n---\n").slice.is_none());
        assert!(parse_baton("---\nitem: 047\n---\n").slice.is_none());
    }

    #[test]
    fn classify_maps_each_status_to_its_disposition() {
        // IN_PROGRESS is the only within-item continue (re-roll the SAME part).
        assert_eq!(classify_status(Some("IN_PROGRESS")), BatonDisposition::Continue);
        assert!(is_continue_status("IN_PROGRESS"));
        // ITEM_COMPLETE / ITEM_DEFERRED are item BOUNDARIES, not within-item
        // continues — the fleet releases the slot, it does not re-roll the part.
        for s in ["ITEM_COMPLETE", "ITEM_DEFERRED"] {
            assert_eq!(classify_status(Some(s)), BatonDisposition::ItemBoundary, "{s}");
            assert!(!is_continue_status(s), "{s} is a boundary, not a within-item continue");
        }
        // The distinct terminal/park statuses the fleet must tell apart.
        assert_eq!(classify_status(Some("QUEUE_EMPTY")), BatonDisposition::QueueEmpty);
        assert_eq!(classify_status(Some("HALTED_RATE_LIMIT")), BatonDisposition::RateLimited);
        assert_eq!(classify_status(Some("BLOCKED_ON_HUMAN")), BatonDisposition::BlockedOnHuman);
        // An agent-written STUCK carries its raw status.
        assert_eq!(
            classify_status(Some("STUCK")),
            BatonDisposition::Stuck("STUCK".to_string())
        );
        // An unrecognized status is also Stuck, carrying the raw text.
        assert_eq!(
            classify_status(Some("FOO")),
            BatonDisposition::Stuck("FOO".to_string())
        );
        // A missing status is the UNKNOWN sentinel → Stuck (no signal to continue on).
        assert_eq!(
            classify_status(None),
            BatonDisposition::Stuck("UNKNOWN".to_string())
        );
        // The view method agrees with the free function.
        let v = parse_baton("---\nstatus: QUEUE_EMPTY\n---\n");
        assert_eq!(v.classify(), BatonDisposition::QueueEmpty);
    }

    #[test]
    fn status_vocabulary_stays_in_step_with_the_classifier() {
        // Every vocabulary entry is a status the classifier recognizes: only the
        // named `STUCK` lands in the catch-all Stuck bucket; the rest map to a
        // concrete disposition (an UNrecognized status would also be Stuck, but is
        // not in the vocabulary). This is the anti-drift guard: a new status added
        // here that the classifier doesn't recognize fails the loop below.
        for &s in STATUS_VOCABULARY {
            let d = classify_status(Some(s));
            if s == "STUCK" {
                assert_eq!(d, BatonDisposition::Stuck("STUCK".to_string()));
            } else {
                assert_ne!(d, BatonDisposition::Stuck(s.to_string()), "{s} must be recognized");
            }
        }

        // And the vocabulary covers EVERY disposition variant at least once, so a
        // new `BatonDisposition` can't be added without a status that yields it.
        let mut seen_continue = false;
        let mut seen_boundary = false;
        let mut seen_queue_empty = false;
        let mut seen_rate_limited = false;
        let mut seen_blocked = false;
        let mut seen_stuck = false;
        for &s in STATUS_VOCABULARY {
            match classify_status(Some(s)) {
                BatonDisposition::Continue => seen_continue = true,
                BatonDisposition::ItemBoundary => seen_boundary = true,
                BatonDisposition::QueueEmpty => seen_queue_empty = true,
                BatonDisposition::RateLimited => seen_rate_limited = true,
                BatonDisposition::BlockedOnHuman => seen_blocked = true,
                BatonDisposition::Stuck(_) => seen_stuck = true,
            }
        }
        assert!(
            seen_continue && seen_boundary && seen_queue_empty && seen_rate_limited && seen_blocked && seen_stuck,
            "the vocabulary must cover every disposition variant",
        );
    }
}
