//! `add_code_review` — task 020 (code-review records).
//!
//! A code review is the third accretive genre: durable numbered records
//! `NNN-slug.md` in a `code-reviews/` folder (primary home
//! `projects/<project>/code-reviews/`; the name is reserved garden-wide).
//! The verb is a thin genre binding over the shared accretive-write core in
//! [`super::add_note`] — the daemon assigns the number, stamps the
//! `# <title>` + `> Last reviewed:` header, refreshes the parent index +
//! backlinks, and mints one `code_review_added` commit. The body is the
//! caller's review markdown (the daemon stamps conventions, never parses
//! it); the expected template lives in the garden's
//! `journal/decisions/decision-softfig-code-review-records.md`.

use softfig_ipc::verbs::{AddCodeReviewArgs, AddCodeReviewReply};
use softfig_ipc::ErrorKind;

use super::add_note::{add_numbered_doc, CODE_REVIEW_GENRE};
use crate::daemon::Daemon;
use crate::handlers::HandlerResult;

pub fn add_code_review(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: AddCodeReviewArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("add_code_review args: {e}")))?;
    let (path, hash) = add_numbered_doc(
        daemon,
        &args.dir,
        &args.slug,
        args.title.as_deref(),
        &args.body,
        &CODE_REVIEW_GENRE,
    )?;
    Ok(serde_json::to_value(AddCodeReviewReply { path, hash }).unwrap())
}
