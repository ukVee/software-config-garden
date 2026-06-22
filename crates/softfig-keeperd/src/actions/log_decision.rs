//! `log_decision` — write `journal/decisions/decision-<slug>.md` with a
//! daemon-stamped header, commit `decision_logged`.

use softfig_vcs::Intent;
use softfig_ipc::verbs::{LogDecisionArgs, LogDecisionReply};
use softfig_ipc::ErrorKind;

use super::{commit_now, conventions, WorkTree};
use crate::daemon::Daemon;
use crate::handlers::{require_unlocked, HandlerResult};

pub fn log_decision(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: LogDecisionArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("log_decision args: {e}")))?;
    conventions::validate_slug(&args.slug)?;
    if args.body.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "body must be non-empty".into()));
    }

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let rel = conventions::decision_path(&args.slug);
    {
        let wt = WorkTree::new(daemon, &inner);
        if wt.exists(&rel) {
            return Err((ErrorKind::PathAlreadyExists, format!("{rel}: already exists")));
        }
        let title = args.summary.as_deref().unwrap_or(&args.slug);
        let content = conventions::decision_doc(title, &conventions::today_hyphen(), &args.body);
        wt.write(&rel, content.as_bytes())?;
    }

    let intent = Intent::new("decision_logged", serde_json::json!({ "slug": args.slug }))
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let inner = &mut *inner;
    let hash = commit_now(inner, intent)?;

    Ok(serde_json::to_value(LogDecisionReply {
        path: rel,
        hash: hash.to_string(),
    })
    .unwrap())
}
