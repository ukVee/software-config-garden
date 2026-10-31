//! `add_command` / `update_command` — the command-doc genre.
//!
//! A command doc is a short, copy-pasteable how-to stored as a numbered
//! `NNN-slug.md` in a `commands/` folder (primary home `os/commands/`; the hub
//! is `os/instructions.md`). The genre is a thin binding over the shared
//! accretive-write core in [`super::add_note`]: `add_command` reuses
//! [`add_numbered_doc`] with [`COMMAND_GENRE`], and `update_command` reuses
//! [`revise_numbered_doc`] with the same genre — so the daemon assigns the
//! number, stamps the `# <title>` + `> Last reviewed:` header, refreshes the
//! parent index + backlinks, and mints `command_added` / `command_updated`
//! provenance. Archiving reuses the generic `archive` verb; cross-referencing
//! rides the automatic `[[…]]` backlink graph.

use softfig_ipc::verbs::{AddCommandArgs, AddCommandReply, UpdateCommandArgs, UpdateCommandReply};
use softfig_ipc::ErrorKind;

use super::add_note::{add_numbered_doc, revise_numbered_doc, COMMAND_GENRE};
use crate::daemon::Daemon;
use crate::handlers::HandlerResult;

pub fn add_command(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: AddCommandArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("add_command args: {e}")))?;
    let (path, hash) = add_numbered_doc(
        daemon,
        &args.dir,
        &args.slug,
        args.title.as_deref(),
        &args.body,
        &COMMAND_GENRE,
    )?;
    Ok(serde_json::to_value(AddCommandReply { path, hash }).unwrap())
}

pub fn update_command(daemon: &Daemon, args: serde_json::Value) -> HandlerResult {
    let args: UpdateCommandArgs = serde_json::from_value(args)
        .map_err(|e| (ErrorKind::BadArgs, format!("update_command args: {e}")))?;
    let (path, hash) = revise_numbered_doc(
        daemon,
        &args.dir,
        args.id,
        &args.body,
        &COMMAND_GENRE,
    )?;
    Ok(serde_json::to_value(UpdateCommandReply { path, hash }).unwrap())
}
