//! The growlight coordination bus — the append-only message store
//! (phase 2, slice 001).
//!
//! A single numbered, `.seq`-backed message log (mirroring `baton-log/`) under
//! `growlight/chat/messages/`, plus a per-agent unread **cursor** under
//! `growlight/chat/cursors/`. Each message carries
//! `{from, to: agent|@all|@human, kind, body, ts}`; `to` selects the
//! recipient's **lane**, and `@all` fans into every agent's lane. `read_inbox`
//! is since-cursor: an agent sees only lane messages numbered above its cursor.
//!
//! This is a **pure store**: no IPC and no MCP wiring. Slice 002 adds the
//! `post_message` / `read_inbox` verbs that call [`append`] / [`unread`] +
//! [`advance_cursor`]; slice 003 surfaces new messages on growlightd's
//! `subscribe` stream. The store binds to the [`Tree`] seam (the daemon's
//! [`super::super::WorkTree`] in production, an in-memory fake in tests), so the
//! whole append / lane / since-cursor / fan-in behaviour is unit-testable with
//! no daemon or mount behind it.
//!
//! `growlight/chat/` is committed (audit + injectable) but, like `baton-log/`,
//! **excluded from the `[[…]]` backlink graph** (`actions::backlinks`): chat is
//! high-churn coordination, so a `[[ref]]` in a message must not forge a
//! backlink edge onto a live item doc.

use softfig_ipc::ErrorKind;

use super::super::{conventions, numbering, Tree};
use super::paths;

type StoreResult<T> = Result<T, (ErrorKind, String)>;

// ---- message model -----------------------------------------------------

/// The closed set of bus message kinds (spec §4a).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageKind {
    Info,
    CoordRequest,
    LeaseRequest,
    Question,
    Alert,
    RestartRequest,
}

impl MessageKind {
    /// Every kind, for validation and iteration.
    pub const ALL: [MessageKind; 6] = [
        MessageKind::Info,
        MessageKind::CoordRequest,
        MessageKind::LeaseRequest,
        MessageKind::Question,
        MessageKind::Alert,
        MessageKind::RestartRequest,
    ];

    /// The on-disk / wire token for this kind.
    pub fn as_wire(self) -> &'static str {
        match self {
            MessageKind::Info => "info",
            MessageKind::CoordRequest => "coord-request",
            MessageKind::LeaseRequest => "lease-request",
            MessageKind::Question => "question",
            MessageKind::Alert => "alert",
            MessageKind::RestartRequest => "restart-request",
        }
    }

    /// Parse a wire token back to a kind. `None` for anything outside the set.
    pub fn parse(token: &str) -> Option<MessageKind> {
        MessageKind::ALL.into_iter().find(|k| k.as_wire() == token)
    }
}

/// A message's addressee. An agent slug, the shared channel (`@all`), or the
/// human (`@human`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Recipient {
    Agent(String),
    All,
    Human,
}

impl Recipient {
    /// The on-disk / wire form: `@all`, `@human`, or the bare agent slug.
    pub fn to_wire(&self) -> String {
        match self {
            Recipient::Agent(a) => a.clone(),
            Recipient::All => "@all".to_string(),
            Recipient::Human => "@human".to_string(),
        }
    }

    /// Parse the wire form. `@all`/`@human` map to the shared/human lanes;
    /// anything else is treated as an agent slug (already validated on append).
    pub fn parse(token: &str) -> Recipient {
        match token {
            "@all" => Recipient::All,
            "@human" => Recipient::Human,
            other => Recipient::Agent(other.to_string()),
        }
    }

    /// A slug-safe label for filenames/display (`all`, `human`, or the slug).
    fn label(&self) -> &str {
        match self {
            Recipient::Agent(a) => a,
            Recipient::All => "all",
            Recipient::Human => "human",
        }
    }
}

/// A message to append: everything but the daemon-assigned number and `ts`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Draft {
    pub from: String,
    pub to: Recipient,
    pub kind: MessageKind,
    pub body: String,
}

/// A stored message: a [`Draft`] plus its monotonic `number` (the total order)
/// and the stamped `ts`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub number: u32,
    pub from: String,
    pub to: Recipient,
    pub kind: MessageKind,
    pub body: String,
    pub ts: String,
}

/// The reserved sender id for the human, who is a first-class bus member.
pub const HUMAN: &str = "@human";

/// A sender is either an agent slug or the human (`@human`). `@all` is a
/// recipient, never a sender.
fn validate_sender(from: &str) -> StoreResult<()> {
    if from == HUMAN {
        Ok(())
    } else {
        conventions::validate_slug(from)
    }
}

// ---- message doc: render + parse ---------------------------------------

/// Render one message as its numbered `NNN-<slug>.md` doc. The metadata block
/// is the parse source ([`parse_message`]); the body follows it verbatim.
fn message_doc(number: u32, draft: &Draft, ts: &str, date_hyphen: &str) -> String {
    let to_wire = draft.to.to_wire();
    format!(
        "# msg {number:03} · {from} → {to_wire}\n\n> Last reviewed: {date_hyphen}\n\n\
         - from: `{from}`\n\
         - to: `{to_wire}`\n\
         - kind: `{kind}`\n\
         - ts: {ts}\n\n\
         {body}\n",
        from = draft.from,
        kind = draft.kind.as_wire(),
        body = draft.body.trim_end_matches('\n'),
    )
}

/// Parse a stored message doc back into a [`Message`]. `number` comes from the
/// filename (the total order), the rest from the metadata block. Returns `None`
/// if the block is missing a field or carries an unknown `kind` — a corrupt
/// entry is skipped, never panics. The body may itself contain `- key:` lines:
/// fields are read only from the contiguous metadata block, never the body.
fn parse_message(number: u32, content: &str) -> Option<Message> {
    let lines: Vec<&str> = content.lines().collect();
    // The metadata block is the run of non-blank lines after the reviewed stamp.
    let stamp = lines.iter().position(|l| l.contains("Last reviewed:"))?;
    let mut i = stamp + 1;
    while i < lines.len() && lines[i].trim().is_empty() {
        i += 1;
    }
    let meta_start = i;
    while i < lines.len() && !lines[i].trim().is_empty() {
        i += 1;
    }
    let meta = &lines[meta_start..i];

    let field = |key: &str| -> Option<String> {
        let prefix = format!("- {key}:");
        meta.iter().find_map(|l| {
            l.trim_start()
                .strip_prefix(&prefix)
                .map(|v| v.trim().trim_matches('`').trim().to_string())
        })
    };

    let from = field("from")?;
    let to = Recipient::parse(&field("to")?);
    let kind = MessageKind::parse(&field("kind")?)?;
    let ts = field("ts")?;

    // Body = everything after the blank line that closes the metadata block.
    let mut b = i;
    while b < lines.len() && lines[b].trim().is_empty() {
        b += 1;
    }
    let body = lines[b..].join("\n").trim_end().to_string();

    Some(Message { number, from, to, kind, body, ts })
}

/// Whether `msg` belongs in `agent`'s lane: a direct message to the agent or a
/// shared `@all` message, but never the agent's own posts (you don't get your
/// own message in your inbox) and never a `@human`-addressed message.
fn in_lane(msg: &Message, agent: &str) -> bool {
    if msg.from == agent {
        return false;
    }
    match &msg.to {
        Recipient::All => true,
        Recipient::Agent(a) => a == agent,
        Recipient::Human => false,
    }
}

// ---- the store (over the [`Tree`] seam) --------------------------------

/// Append `draft` as the next numbered message, stamping `ts`. Bumps the
/// channel `.seq` and writes the doc through `tree` (so a caller's in-flight
/// commit folds it in), exactly like `log_baton`. Returns the stored
/// [`Message`]. Validates the sender (agent slug or `@human`), a non-empty
/// body, and — for a direct message — the recipient slug.
pub fn append<T: Tree>(tree: &T, draft: &Draft, ts: &str) -> StoreResult<Message> {
    validate_sender(&draft.from)?;
    if let Recipient::Agent(a) = &draft.to {
        conventions::validate_slug(a)?;
    }
    if draft.body.trim().is_empty() {
        return Err((ErrorKind::BadArgs, "message body must be non-empty".into()));
    }

    let dir = paths::chat_messages_dir();
    let number = numbering::next_number(tree, &dir);
    let rel = message_rel(number, draft);
    let content = message_doc(number, draft, ts, &conventions::today_hyphen());
    numbering::write_numbered(tree, &dir, number, &rel, &content)?;

    Ok(Message {
        number,
        from: draft.from.clone(),
        to: draft.to.clone(),
        kind: draft.kind,
        body: draft.body.clone(),
        ts: ts.to_string(),
    })
}

/// A sender's slug-safe label (`@human` → `human`, else the slug as-is).
fn sender_label(from: &str) -> &str {
    if from == HUMAN {
        "human"
    } else {
        from
    }
}

/// The garden-relative path a message with this `number` and `draft` is stored
/// at — the single source of truth for the message filename, shared by
/// [`append`] (when it writes) and the `post_message` verb (to report `path`).
pub fn message_rel(number: u32, draft: &Draft) -> String {
    let dir = paths::chat_messages_dir();
    let slug = conventions::slugify(&format!(
        "{}-to-{}",
        sender_label(&draft.from),
        draft.to.label()
    ));
    format!("{dir}/{}", conventions::note_filename(number, &slug))
}

/// Every message in the channel, in total order (ascending `number`). Corrupt
/// docs are skipped (see [`parse_message`]).
pub fn all_messages<T: Tree>(tree: &T) -> Vec<Message> {
    let dir = paths::chat_messages_dir();
    let mut msgs: Vec<Message> = tree
        .read_dir(&dir)
        .iter()
        .filter_map(|e| {
            let number = conventions::parse_note_number(&e.name)?;
            let content = tree.read_to_string(&format!("{dir}/{}", e.name))?;
            parse_message(number, &content)
        })
        .collect();
    msgs.sort_by_key(|m| m.number);
    msgs
}

/// Every message in `agent`'s lane, in total order — direct messages to it and
/// `@all` messages, minus its own posts.
// The since-cursor `unread` is what the slice-002 verb reads; the full `lane`
// view is exercised by the store tests and is the seam slice 003's subscribe
// fan-out renders from.
#[allow(dead_code)]
pub fn lane<T: Tree>(tree: &T, agent: &str) -> Vec<Message> {
    all_messages(tree)
        .into_iter()
        .filter(|m| in_lane(m, agent))
        .collect()
}

/// `agent`'s unread-cursor: the highest message number it has consumed (0 if it
/// has never read). The cursor is daemon-owned, like `.seq`.
pub fn cursor<T: Tree>(tree: &T, agent: &str) -> u32 {
    tree.read_to_string(&paths::chat_cursor(agent))
        .and_then(|s| s.trim().parse::<u32>().ok())
        .unwrap_or(0)
}

/// Advance `agent`'s cursor to `number` (writes through `tree`; the caller
/// commits). Monotonic: a lower `number` is ignored so a re-read can't rewind.
pub fn advance_cursor<T: Tree>(tree: &T, agent: &str, number: u32) -> StoreResult<()> {
    if number <= cursor(tree, agent) {
        return Ok(());
    }
    tree.write(&paths::chat_cursor(agent), format!("{number}\n").as_bytes())
}

/// `agent`'s unread lane messages — its lane filtered to numbers above its
/// stored cursor, in total order. This is the since-cursor `read_inbox` view;
/// the slice-002 verb advances the cursor after delivering.
pub fn unread<T: Tree>(tree: &T, agent: &str) -> Vec<Message> {
    let since = cursor(tree, agent);
    all_messages(tree)
        .into_iter()
        .filter(|m| m.number > since && in_lane(m, agent))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::actions::worktree::DirEntry;
    use std::cell::RefCell;
    use std::collections::BTreeMap;

    /// In-memory [`Tree`] fake: a flat path → bytes map, no daemon or mount.
    #[derive(Default)]
    struct MemTree {
        files: RefCell<BTreeMap<String, Vec<u8>>>,
    }

    impl Tree for MemTree {
        fn read_to_string(&self, rel: &str) -> Option<String> {
            self.files
                .borrow()
                .get(rel)
                .map(|b| String::from_utf8_lossy(b).into_owned())
        }
        fn read_dir(&self, rel: &str) -> Vec<DirEntry> {
            let prefix = format!("{rel}/");
            let mut seen: BTreeMap<String, bool> = BTreeMap::new();
            for k in self.files.borrow().keys() {
                if let Some(rest) = k.strip_prefix(&prefix) {
                    match rest.split_once('/') {
                        Some((dir, _)) => {
                            seen.insert(dir.to_string(), true);
                        }
                        None => {
                            seen.insert(rest.to_string(), false);
                        }
                    }
                }
            }
            seen.into_iter()
                .map(|(name, is_dir)| DirEntry { name, is_dir })
                .collect()
        }
        fn exists(&self, rel: &str) -> bool {
            let f = self.files.borrow();
            f.contains_key(rel) || f.keys().any(|k| k.starts_with(&format!("{rel}/")))
        }
        fn write(&self, rel: &str, bytes: &[u8]) -> Result<(), (ErrorKind, String)> {
            self.files.borrow_mut().insert(rel.to_string(), bytes.to_vec());
            Ok(())
        }
    }

    fn draft(from: &str, to: Recipient, body: &str) -> Draft {
        Draft { from: from.into(), to, kind: MessageKind::Info, body: body.into() }
    }

    #[test]
    fn message_doc_round_trips_even_with_dashed_body() {
        // A body that itself contains `- key:` lines must not corrupt the parse.
        let d = Draft {
            from: "agent-a".into(),
            to: Recipient::Agent("agent-b".into()),
            kind: MessageKind::CoordRequest,
            body: "please rebase\n- from: not-a-field\n- to: also-not".into(),
        };
        let doc = message_doc(7, &d, "2026-06-22T10:00:00Z", "2026-06-22");
        let got = parse_message(7, &doc).expect("parses");
        assert_eq!(got.number, 7);
        assert_eq!(got.from, "agent-a");
        assert_eq!(got.to, Recipient::Agent("agent-b".into()));
        assert_eq!(got.kind, MessageKind::CoordRequest);
        assert_eq!(got.ts, "2026-06-22T10:00:00Z");
        assert_eq!(got.body, "please rebase\n- from: not-a-field\n- to: also-not");
    }

    #[test]
    fn every_kind_and_recipient_round_trips() {
        for kind in MessageKind::ALL {
            for to in [
                Recipient::All,
                Recipient::Human,
                Recipient::Agent("roudy".into()),
            ] {
                let d = Draft { from: "src".into(), to: to.clone(), kind, body: "b".into() };
                let doc = message_doc(1, &d, "ts", "2026-06-22");
                let got = parse_message(1, &doc).expect("parses");
                assert_eq!(got.kind, kind);
                assert_eq!(got.to, to);
            }
        }
    }

    #[test]
    fn append_numbers_monotonically_and_bumps_seq() {
        let t = MemTree::default();
        let m1 = append(&t, &draft("a", Recipient::All, "one"), "t1").unwrap();
        let m2 = append(&t, &draft("a", Recipient::All, "two"), "t2").unwrap();
        let m3 = append(&t, &draft("a", Recipient::All, "three"), "t3").unwrap();
        assert_eq!((m1.number, m2.number, m3.number), (1, 2, 3));
        // Stored under the channel's messages dir with a bumped `.seq`.
        assert_eq!(
            t.read_to_string(&format!("{}/.seq", paths::chat_messages_dir())).as_deref(),
            Some("3\n")
        );
    }

    #[test]
    fn all_messages_is_total_ordered_regardless_of_dir_order() {
        let t = MemTree::default();
        // Plant docs out of numeric order; all_messages must sort by number.
        for (n, body) in [(3, "c"), (1, "a"), (2, "b")] {
            let rel = format!("{}/{n:03}-x.md", paths::chat_messages_dir());
            let doc = message_doc(n, &draft("a", Recipient::All, body), "ts", "2026-06-22");
            t.write(&rel, doc.as_bytes()).unwrap();
        }
        let nums: Vec<u32> = all_messages(&t).iter().map(|m| m.number).collect();
        assert_eq!(nums, vec![1, 2, 3]);
    }

    #[test]
    fn at_all_fans_into_every_lane_direct_targets_one() {
        let t = MemTree::default();
        append(&t, &draft("a", Recipient::All, "hello all"), "t1").unwrap();
        append(&t, &draft("a", Recipient::Agent("b".into()), "hi b"), "t2").unwrap();
        append(&t, &draft("a", Recipient::Human, "hi human"), "t3").unwrap();

        // @all reaches every other agent's lane (fan-in); the direct msg only b.
        let b_lane: Vec<u32> = lane(&t, "b").iter().map(|m| m.number).collect();
        assert_eq!(b_lane, vec![1, 2]);
        let c_lane: Vec<u32> = lane(&t, "c").iter().map(|m| m.number).collect();
        assert_eq!(c_lane, vec![1]); // only the @all message
        // The author never sees its own posts (incl. its own @all).
        assert!(lane(&t, "a").is_empty());
    }

    #[test]
    fn human_addressed_messages_are_in_no_agent_lane() {
        let t = MemTree::default();
        append(&t, &draft("a", Recipient::Human, "for the human"), "t1").unwrap();
        assert!(lane(&t, "b").is_empty());
        assert!(lane(&t, "c").is_empty());
    }

    #[test]
    fn unread_is_since_cursor_and_advance_is_monotonic() {
        let t = MemTree::default();
        for i in 0..3 {
            append(&t, &draft("a", Recipient::All, &format!("m{i}")), "t").unwrap();
        }
        // b has read nothing → all three are unread.
        assert_eq!(unread(&t, "b").iter().map(|m| m.number).collect::<Vec<_>>(), vec![1, 2, 3]);

        advance_cursor(&t, "b", 2).unwrap();
        assert_eq!(cursor(&t, "b"), 2);
        assert_eq!(unread(&t, "b").iter().map(|m| m.number).collect::<Vec<_>>(), vec![3]);

        // A new message lands after the cursor; a stale (lower) advance is a no-op.
        append(&t, &draft("a", Recipient::All, "m3"), "t").unwrap();
        advance_cursor(&t, "b", 1).unwrap(); // ignored — cursor must not rewind
        assert_eq!(cursor(&t, "b"), 2);
        assert_eq!(unread(&t, "b").iter().map(|m| m.number).collect::<Vec<_>>(), vec![3, 4]);
    }

    #[test]
    fn cursors_are_per_agent() {
        let t = MemTree::default();
        for _ in 0..4 {
            append(&t, &draft("a", Recipient::All, "m"), "t").unwrap();
        }
        advance_cursor(&t, "b", 3).unwrap();
        // c's cursor is independent of b's.
        assert_eq!(cursor(&t, "c"), 0);
        assert_eq!(unread(&t, "c").len(), 4);
        assert_eq!(unread(&t, "b").iter().map(|m| m.number).collect::<Vec<_>>(), vec![4]);
    }

    #[test]
    fn append_validates_sender_recipient_and_body() {
        let t = MemTree::default();
        // Bad sender slug.
        assert!(append(&t, &draft("Bad Sender", Recipient::All, "x"), "t").is_err());
        // The human is a valid sender.
        assert!(append(&t, &draft(HUMAN, Recipient::All, "x"), "t").is_ok());
        // Bad direct-recipient slug.
        assert!(append(&t, &draft("a", Recipient::Agent("Bad".into()), "x"), "t").is_err());
        // Empty body.
        assert!(append(&t, &draft("a", Recipient::All, "   "), "t").is_err());
    }
}
