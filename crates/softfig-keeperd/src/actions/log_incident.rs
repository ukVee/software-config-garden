//! `log_incident` — write `journal/incidents/incident-<date>-<slug>.md`
//! with a daemon-stamped header, commit `incident_logged`.

use softfig_vcs::Intent;
use softfig_ipc::verbs::{LogIncidentArgs, LogIncidentReply};
use softfig_ipc::ErrorKind;

use super::{commit_now, conventions, WorkTree};
use crate::daemon::Daemon;
use crate::handlers::{require_unlocked, HandlerResult};

pub fn log_incident(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: LogIncidentArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("log_incident args: {e}")))?;
    conventions::validate_slug(&args.slug)?;
    if args.summary.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "summary must be non-empty".into()));
    }
    if args.body.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "body must be non-empty".into()));
    }

    let date = match &args.date {
        Some(d) => {
            conventions::validate_incident_date(d)?;
            d.clone()
        }
        None => conventions::today_compact(),
    };

    let mut inner = daemon.inner.lock().unwrap();
    require_unlocked(&inner)?;

    let rel = conventions::incident_path(&date, &args.slug);
    {
        let wt = WorkTree::new(daemon, &inner);
        if wt.exists(&rel) {
            return Err((ErrorKind::PathAlreadyExists, format!("{rel}: already exists")));
        }
        let hyphen = conventions::compact_to_hyphen(&date);
        let content = conventions::incident_doc(&hyphen, &args.summary, &args.body);
        wt.write(&rel, content.as_bytes())?;
    }

    // Classifier-compatible payload: the slug is the full
    // `incident-<date>-<slug>` stem (matches the watcher's `incident_logged`
    // rule).
    let full_slug = format!("incident-{date}-{}", args.slug);
    let intent = Intent::new("incident_logged", serde_json::json!({ "slug": full_slug }))
        .map_err(|e| (ErrorKind::Internal, e.to_string()))?;
    let inner = &mut *inner;
    let hash = commit_now(inner, intent)?;

    Ok(serde_json::to_value(LogIncidentReply {
        path: rel,
        hash: hash.to_string(),
    })
    .unwrap())
}
