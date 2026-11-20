//! soft-fig IPC: a **facade** for in-repo consumers, not a public surface,
//! and no longer the protocol itself (`docs/protocol-stability.md`).
//!
//! `feat/tui-split-protocol` moved the wire out; every moved item is
//! re-exported here unchanged, so every pre-split `softfig_ipc::...` path
//! still compiles. A frontend depends on the concrete crate; this facade is
//! what keeps the daemons and the CLI unedited (the mergeability argument in
//! `meta/spec-softfig-tui-frontend-split.md` §3).
//!
//! - `softfig-protocol-keeperd` — the JSON-Lines envelope (`Request`,
//!   `Response`, `ErrorKind`), the keeperd verb types, `PROTOCOL_VERSION`, and
//!   the pure value rules the wire surface reads:
//!   `fleet::{holds, parse_not_before, days_from_civil}` and
//!   `queue_v2::{EntryKind, Lane, SliceStatus, RestackBranch,
//!   hold_annotation}` with the IO-free `queue_v2::migrate::{Answers,
//!   BatonMove, CallClass}`.
//! - `softfig-protocol-growlightd` — the growlightd wire types (`growlightd`).
//! - `softfig-client` — `client`, `socket`, and the reconnecting call.
//!
//! What is left here is the daemon-shared garden code: `backlog_doc`, `baton`,
//! `claude_profiles`, `item_meta`, `item_repo`, `member`, `model_choice`,
//! `opencode`, `slot_name`, `testing`, `tz`, `usage`, the `queue_v2` state-file
//! half (`validate`, and the IO-bound `migrate` plan) and the `fleet` item-doc
//! scanner.
//!
//! Wire format: one JSON object per line, `\n`-terminated. Both directions
//! identical. See `meta/spec-keeper.md` "IPC protocol" in the soft-fig
//! garden for the design rationale.

#![deny(unsafe_code)]
#![warn(missing_debug_implementations)]

pub mod backlog_doc;
pub mod baton;
pub mod claude_profiles;
pub mod fleet;
pub mod item_meta;
pub mod item_repo;
pub mod member;
pub mod model_choice;
pub mod opencode;
pub mod queue_v2;
pub mod slot_name;
pub mod testing;
pub mod tz;
pub mod usage;

pub use baton::{classify_status, parse_baton, BatonDisposition, BatonView};
pub use fleet::fleet_marker;
pub use member::{is_safe_member_id, MemberIdentity, MEMBER_ENV};
pub use model_choice::{
    Backend, Declaration, DeclaredModels, ModelChoice, ModelList, ModelRuleError, ModelSpec,
    item_doc_candidates, item_doc_candidates_listed, item_model_field, member_default,
    parse_declaration, parse_model_spec, resolve_item_models, validate_declared_subset,
    validate_model_change,
};
pub use slot_name::{validate_slot_name, SlotNameError};
pub use queue_v2::{
    sub_depth, ArchivedEntry, Entry, EntryKind, EntryStatus, FinalStatus, Lane, Project,
    QueueArchiveToml, QueueRefusal, QueueToml, QueueV2Error, SliceItem, SliceKind, SliceStatus,
    SlicesToml,
};
pub use softfig_client::{client, socket};
pub use softfig_client::{
    call, call_reconnecting, connect, connect_stream, ClientError, ReconnectError, RetryPolicy,
};
pub use softfig_client::{growlightd_runtime_socket_path, runtime_socket_path};
pub use softfig_protocol_growlightd::growlightd;
pub use softfig_protocol_keeperd::{proto, verbs, PROTOCOL_VERSION};
pub use softfig_protocol_keeperd::proto::{ErrorKind, Request, Response};
pub use softfig_protocol_keeperd::verbs::*;

/// The in-garden config directory (`<garden_root>/config/`) holding the
/// encrypted, versioned, M5b-backed daemon config files.
pub const GARDEN_CONFIG_DIR: &str = "config";

/// The in-garden fleet config file, relative to the garden root
/// (`<garden_root>/config/growlight.toml`). growlightd reads the full fleet
/// schema (gate + roster) from it through the mount; keeperd reads only its
/// `fleet_enabled` gate to decide whether to start the growlightd unit on
/// unlock. Shared here so those two readers — in separate crates that can't
/// depend on each other — can never drift on the path. See
/// `journal/decisions/decision-growlight-config-in-garden.md`.
pub const GROWLIGHT_CONFIG_FILE: &str = "growlight.toml";
