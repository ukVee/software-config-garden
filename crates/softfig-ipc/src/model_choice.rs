//! The `> Model:` grammar and its resolution — `spec-growlight-queue` §6.4
//! (the model rule) and §6.7 (the slice-body subset rule).
//!
//! Moved here from `softfig-cli` (`semi-auto-backend-seam`, 2026-08-08) so the
//! semi-auto launcher and growlightd's v2 scheduling resolve the same way, and
//! the grants spec can depend on the same grammar. What moved is the pure
//! grammar + resolution; the CLI's launch machinery (argv/env construction)
//! stays in the CLI.
//!
//! The legacy trap (§6.4): semi-auto's "let growlight decide" takes a comma
//! list's **first** entry, and the live garden keeps every `> Model:` line
//! single-entry until the migration flips the switch.

use std::fmt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result, bail};

use crate::queue_v2::milestone_path;

/// DeepSeek's reasoning model — picker option 2 / `--model reasoning`. The
/// version-pinned top-tier V4 rather than the floating `deepseek/deepseek-reasoner`
/// alias (the human's call, 2026-08-08, closing the slice-005 open sub-question),
/// so the loop's model can't move under it without a code change.
pub const DEEPSEEK_REASONING: &str = "deepseek/deepseek-v4-pro";

/// DeepSeek's fast model — picker option 3 / `--model flash`, and the fallback
/// whenever "let growlight decide" finds no `> Model:` declaration on the active
/// backlog item (cheap by default; reasoning is opt-in).
///
/// V4.1 Flash. The earlier `deepseek/deepseek-v4-flash` id is gone from opencode
/// 2.x's catalog (opencode-v2-repin slice 001, finding 12).
pub const DEEPSEEK_FLASH: &str = "deepseek/deepseek-flash";

/// Which agent backend runs a unit (§6.4 backend match): `claude` ↔ the claude
/// backend, every other spec ↔ opencode.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Backend {
    /// Claude Code (`claude`) — the semi-auto default.
    #[default]
    Claude,
    /// opencode.
    Opencode,
}

impl fmt::Display for Backend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Backend::Claude => "claude",
            Backend::Opencode => "opencode",
        })
    }
}

impl FromStr for Backend {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "claude" => Ok(Backend::Claude),
            "opencode" => Ok(Backend::Opencode),
            other => bail!("unknown backend `{other}` (expected claude | opencode)"),
        }
    }
}

/// A resolved launch target: which backend, and (for opencode) which model +
/// variant to generate the agent config with.
///
/// `model`/`variant` are opencode-only. claude's model + effort are the harness's
/// own (there is no interactive flag for them), so a claude choice carries `None`
/// and a `variant=` on a claude spec is inert — see [`parse_model_spec`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelChoice {
    pub backend: Backend,
    /// The opencode model id (`provider/model`), e.g. [`DEEPSEEK_FLASH`].
    pub model: Option<String>,
    /// The opencode agent's `variant` (opencode `AgentConfig.variant`: "default
    /// model variant for this agent") — the effort/variant knob a backlog item
    /// can declare alongside its model.
    pub variant: Option<String>,
}

impl ModelChoice {
    /// The claude backend: no model/variant of our choosing (the harness owns them).
    pub fn claude() -> Self {
        Self {
            backend: Backend::Claude,
            model: None,
            variant: None,
        }
    }

    /// The opencode backend on a given model id.
    pub fn opencode(model: &str) -> Self {
        Self {
            backend: Backend::Opencode,
            model: Some(model.to_string()),
            variant: None,
        }
    }

    /// The model id to generate the opencode config with, falling back to
    /// [`DEEPSEEK_FLASH`] for a choice that names none.
    pub fn opencode_model(&self) -> &str {
        self.model.as_deref().unwrap_or(DEEPSEEK_FLASH)
    }

    /// The model + variant as opencode 2.x spells one value:
    /// `provider/model`, or `provider/model#variant`.
    pub fn opencode_model_ref(&self) -> String {
        match &self.variant {
            Some(variant) => format!("{}#{variant}", self.opencode_model()),
            None => self.opencode_model().to_string(),
        }
    }

    /// Same model identity (backend + model id), variant ignored — the §6.4
    /// "variant changes are free within an allowed model" match.
    pub fn matches(&self, other: &ModelChoice) -> bool {
        self.backend == other.backend
            && match (&self.model, &other.model) {
                (Some(a), Some(b)) => a == b,
                (None, None) => true,
                _ => false,
            }
    }
}

/// What a `--model` flag or a picker choice resolves to *before* the active
/// backlog item is consulted.
///
/// `Auto` is "let growlight decide": rather than guessing from the work's shape,
/// growlight reads the model the **active backlog item declares for itself** — the
/// optional `> Model: <spec>` line on its slice doc (falling back to the milestone
/// doc, then to [`DEEPSEEK_FLASH`]). The human writes the field when they queue the
/// work, where the judgement actually belongs; the launcher only obeys it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ModelSpec {
    /// Resolve from the active backlog item's declared `> Model:` field.
    Auto,
    /// A choice made outright, with no item lookup.
    Fixed(ModelChoice),
}

/// Parse a model spec — the shared grammar behind `--model <spec>`, the picker,
/// and a backlog item's `> Model:` line, so all three accept exactly the same
/// words. Pure.
///
/// `<token> [key=value …]` where `<token>` is one of:
///   - `claude` — the claude backend.
///   - `reasoning` / `deepseek-reasoning` → opencode on [`DEEPSEEK_REASONING`].
///   - `flash` / `deepseek-flash` → opencode on [`DEEPSEEK_FLASH`].
///   - `auto` → [`ModelSpec::Auto`] (only meaningful from the CLI/picker; an item
///     doc that declares `auto` would be circular, so callers treat it as absent).
///   - any `provider/model` id → opencode on that id verbatim (an escape hatch for
///     a model neither alias covers; opencode validates it at launch).
///
/// The optional `key=value` tail carries the effort/variant knob: `variant=<v>`
/// (or its alias `effort=<v>`) sets the opencode agent's `variant`. It is inert on
/// a `claude` spec — claude's effort isn't settable from this launch path — so it
/// parses without error and is simply not carried.
pub fn parse_model_spec(spec: &str) -> Result<ModelSpec> {
    let mut words = spec.split_whitespace();
    let Some(token) = words.next() else {
        bail!("empty model spec");
    };

    let mut variant: Option<String> = None;
    for pair in words {
        let (key, value) = pair
            .split_once('=')
            .ok_or_else(|| anyhow::anyhow!("model spec: expected `key=value`, got `{pair}` in `{spec}`"))?;
        match key {
            // `effort` is accepted as an alias so the field reads naturally for
            // either mental model; both land on opencode's one `variant` knob.
            // An empty value is a typo, not "no variant" — emitting `"variant": ""`
            // would pin the agent to a nameless variant.
            "variant" | "effort" if value.is_empty() => {
                bail!("model spec: `{key}=` has no value in `{spec}`")
            }
            // The variant is rendered after a `#` (`provider/model#variant`), so
            // one carrying its own `#` could not be read back unambiguously.
            "variant" | "effort" if value.contains('#') => {
                bail!("model spec: `{key}={value}` contains '#' in `{spec}`")
            }
            "variant" | "effort" => variant = Some(value.to_string()),
            _ => bail!("model spec: unknown key `{key}` in `{spec}` (expected `variant=`)"),
        }
    }

    let mut choice = match token.to_ascii_lowercase().as_str() {
        "auto" => {
            if variant.is_some() {
                bail!("model spec: `auto` takes no `variant=` — declare it on the item instead");
            }
            return Ok(ModelSpec::Auto);
        }
        "claude" => ModelChoice::claude(),
        "reasoning" | "deepseek-reasoning" => ModelChoice::opencode(DEEPSEEK_REASONING),
        "flash" | "deepseek-flash" => ModelChoice::opencode(DEEPSEEK_FLASH),
        // A `#variant` suffix on the id is opencode's own spelling, but here the
        // variant has exactly one home (`variant=`), so the two cannot disagree.
        other if other.contains('#') => bail!(
            "model spec: `{token}` carries a '#variant' suffix — write it as \
             `{} variant={}` instead",
            token.split_once('#').map_or(token, |(m, _)| m),
            token.split_once('#').map_or("", |(_, v)| v),
        ),
        // A raw `provider/model` passthrough — anything else is a typo, not a model.
        other if other.contains('/') => ModelChoice::opencode(token),
        other => bail!(
            "unknown model `{other}` — expected claude | reasoning | flash | auto | provider/model"
        ),
    };
    // Inert on claude (the harness owns its effort), carried on opencode.
    if choice.backend == Backend::Opencode {
        choice.variant = variant;
    }
    Ok(ModelSpec::Fixed(choice))
}

/// Pull a backlog item's optional `> Model: <spec>` declaration out of its doc.
///
/// The field rides the same leading blockquote metadata block the item docs
/// already use for `> Last reviewed:` / `> Design:`, so declaring a model is one
/// line and needs no new file. Read through the shared scanner
/// ([`crate::item_meta::field`]): only a blockquote line counts — prose
/// mentioning a model can't be mistaken for a declaration — a line inside a
/// fenced example doesn't, and the first one wins (an empty first line is no
/// declaration). Pure.
pub fn item_model_field(doc: &str) -> Option<&str> {
    crate::item_meta::field(doc, crate::item_meta::MODEL).filter(|v| !v.is_empty())
}

/// An ordered, non-empty list of model specs — the comma-list form of §6.4
/// (`> Model: reasoning, flash variant=high`). Order matters: a member runs the
/// FIRST listed model its backend can run. A single-entry line parses to a
/// one-entry list, so today's docs resolve exactly as before.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModelList {
    entries: Vec<ModelChoice>,
}

impl ModelList {
    /// A single-entry list (today's form).
    pub fn single(choice: ModelChoice) -> Self {
        Self {
            entries: vec![choice],
        }
    }

    /// The entries, in declared order. Never empty.
    pub fn entries(&self) -> &[ModelChoice] {
        &self.entries
    }

    /// The first entry — what semi-auto's "let growlight decide" runs (§6.4
    /// legacy trap: a comma list resolves to its first entry).
    pub fn first(&self) -> &ModelChoice {
        &self.entries[0]
    }

    /// The first listed model `backend` can run, if any (§6.4 backend match).
    pub fn first_for_backend(&self, backend: Backend) -> Option<&ModelChoice> {
        self.entries.iter().find(|e| e.backend == backend)
    }

    /// Whether `backend` runs at least one listed model — the §6.4 gate for a
    /// member taking the unit.
    pub fn backend_can_run(&self, backend: Backend) -> bool {
        self.first_for_backend(backend).is_some()
    }

    /// Whether the list names `other`'s model identity ([`ModelChoice::matches`],
    /// variant ignored).
    pub fn contains(&self, other: &ModelChoice) -> bool {
        self.entries.iter().any(|e| e.matches(other))
    }
}

/// What a doc's `> Model:` field declared (§6.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Declaration {
    /// The field is a lone `auto` spec — circular on an item doc (the item
    /// would be choosing the chooser), so callers treat it as no declaration
    /// and keep walking the chain.
    Auto,
    /// A non-empty ordered list of specs.
    List(ModelList),
}

/// Parse a doc's `> Model:` field into a [`Declaration`]. Entries split on
/// commas; each entry is trimmed and parsed with [`parse_model_spec`]. An empty
/// entry (a trailing or doubled comma) is a typo, and `auto` may not appear in
/// a list — both refused.
pub fn parse_declaration(field: &str) -> Result<Declaration> {
    let entries: Vec<&str> = field.split(',').map(str::trim).collect();
    if let Some(empty_at) = entries.iter().position(|e| e.is_empty()) {
        bail!("model list: entry {} is empty in `{field}`", empty_at + 1);
    }
    let mut specs = Vec::with_capacity(entries.len());
    for (i, entry) in entries.iter().enumerate() {
        match parse_model_spec(entry).with_context(|| format!("model list entry {}", i + 1))? {
            ModelSpec::Fixed(choice) => specs.push(choice),
            ModelSpec::Auto => {
                if entries.len() == 1 {
                    return Ok(Declaration::Auto);
                }
                bail!("model list: `auto` cannot appear in a list (`{field}`)");
            }
        }
    }
    Ok(Declaration::List(ModelList { entries: specs }))
}

/// The allowed list for a unit that declares nothing (§6.4 member default): a
/// single model — the opencode roster's `model` + `variant` (or
/// [`DEEPSEEK_FLASH`] when they're absent), or `claude` for a claude member.
pub fn member_default(
    backend: Backend,
    roster_model: Option<&str>,
    roster_variant: Option<&str>,
) -> ModelList {
    match backend {
        Backend::Claude => ModelList::single(ModelChoice::claude()),
        Backend::Opencode => {
            let mut choice = ModelChoice::opencode(roster_model.unwrap_or(DEEPSEEK_FLASH));
            choice.variant = roster_variant.map(str::to_string);
            ModelList::single(choice)
        }
    }
}

/// A model-rule refusal. Both spell the spec's one `model_not_allowed` code
/// (§6.4 `model_change`, §6.7 subset rule); the verb layer maps them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ModelRuleError {
    /// The requested model is not in the unit's allowed list.
    #[error("model_not_allowed: the requested model is not in the unit's allowed list")]
    NotAllowed,
    /// The unit inherits no declaration, so the new slice may declare none.
    #[error("model_not_allowed: the unit inherits no declaration, so none may be declared")]
    DeclaresWithoutInheritance,
}

/// §6.4 `model_change` validation: a request may name any listed model, a
/// variant change is free within an allowed model, and a unit that declared
/// nothing (`declared = false` — its allowed list is the member default) allows
/// no change at all.
pub fn validate_model_change(
    allowed: &ModelList,
    requested: &ModelChoice,
    declared: bool,
) -> Result<(), ModelRuleError> {
    if declared && allowed.contains(requested) {
        Ok(())
    } else {
        Err(ModelRuleError::NotAllowed)
    }
}

/// §6.7 subset rule for a slice body's declared list: it must be a subset of
/// what the new slice would inherit without it, and an inherited "nothing
/// declared" means it may declare nothing.
pub fn validate_declared_subset(
    inherited: Option<&ModelList>,
    declared: &ModelList,
) -> Result<(), ModelRuleError> {
    match inherited {
        None => Err(ModelRuleError::DeclaresWithoutInheritance),
        Some(inherited) if declared.entries().iter().all(|e| inherited.contains(e)) => Ok(()),
        Some(_) => Err(ModelRuleError::NotAllowed),
    }
}

/// The backlog prefix both v2 state paths hang off.
const BACKLOG_DIR: &str = "growlight/backlog";

/// Where an active item's `> Model:` declaration may live, nearest first — the
/// §6.4 resolution chain:
///
/// - a milestone or sub-milestone: the active slice's own doc, then each
///   enclosing sub-milestone's `CLAUDE.md` (innermost first), then the
///   milestone's `CLAUDE.md`;
/// - a task or restack: just its doc.
///
/// A sub-milestone identity is `"<parent>/<sub-slug>"` (§3.3); the on-disk
/// layout funnels through [`milestone_path`]. Slice filenames carry a slug we
/// don't know (`005-backend-model-picker.md`), so each is found by its
/// zero-padded numeric prefix rather than reconstructed. Batons write the slice
/// unpadded (`6`) as often as padded; the files are always zero-padded.
///
/// `Err` when two docs share the number being looked up: which one declares the
/// model is then a guess, and a second `NNN-*.md` beside the real one is
/// exactly how a shadow doc would steer it (review 042 G74-2), so the lookup
/// fails closed instead of taking the first.
pub fn item_doc_candidates(
    garden_root: &Path,
    item: &str,
    slice: Option<&str>,
) -> Result<Vec<PathBuf>, String> {
    let backlog = garden_root.join(BACKLOG_DIR);
    let top = item.split('/').next().unwrap_or(item);
    if !backlog.join("milestones").join(top).is_dir() {
        // A task (or restack) doc: the single file for the whole chain. A
        // restack's generated doc is queue-v2-git's row; until that lands, the
        // task lookup is the only non-milestone shape.
        return Ok(find_by_number(&backlog.join("tasks"), item)?.into_iter().collect());
    }

    let mut candidates = Vec::new();
    // The active slice's doc lives in the item's own (innermost) slices dir.
    if let Some(slice) = slice {
        let padded = format!("{:0>3}", slice.trim());
        let slices = garden_root.join(milestone_path(item)).join("slices");
        if let Some(doc) = find_by_number(&slices, &padded)? {
            candidates.push(doc);
        }
    }
    // Enclosing CLAUDE.mds, innermost first, up to the top milestone.
    let parts: Vec<&str> = item.split('/').collect();
    for depth in (0..parts.len()).rev() {
        let identity = parts[..=depth].join("/");
        candidates.push(garden_root.join(milestone_path(&identity)).join("CLAUDE.md"));
    }
    Ok(candidates)
}

/// The `NNN-<slug>.md` file in `dir` whose numeric prefix is `number`:
/// `Ok(None)` when there is none (or `dir` is absent), `Err` when more than one
/// matches (see [`item_doc_candidates`]).
fn find_by_number(dir: &Path, number: &str) -> Result<Option<PathBuf>, String> {
    let Ok(listing) = std::fs::read_dir(dir) else {
        return Ok(None);
    };
    let names: Vec<String> = listing
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .collect();
    Ok(unique_numbered(names.iter().map(String::as_str), number)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .map(|name| dir.join(name)))
}

/// The one `<number>-*.md` name among `names`: `Ok(None)` when none matches,
/// `Err` naming every match when more than one does — two docs claiming one
/// item or slice number make every reader's answer a guess, so each fails
/// closed (review 042 G74-2). Shared by the model resolver here and
/// growlightd's claim-time item-doc read.
pub fn unique_numbered<'a>(
    names: impl IntoIterator<Item = &'a str>,
    number: &str,
) -> Result<Option<&'a str>, String> {
    let prefix = format!("{number}-");
    let mut matches: Vec<&str> = names
        .into_iter()
        .filter(|n| n.starts_with(&prefix) && n.ends_with(".md"))
        .collect();
    match matches.len() {
        0 => Ok(None),
        1 => Ok(matches.pop()),
        _ => {
            matches.sort_unstable();
            Err(format!(
                "{} docs share number {number} ({}) — ambiguous, so none is trusted until one is \
                 removed",
                matches.len(),
                matches.join(", ")
            ))
        }
    }
}

/// A resolved declaration, with the declaring doc for messages.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeclaredModels {
    /// The declared list, in order.
    pub list: ModelList,
    /// The declaring doc's file name (e.g. `005-picker.md`), for messages.
    pub origin: String,
    /// The raw `> Model:` field, as written.
    pub field: String,
}

/// Walk the §6.4 resolution chain — docs as `(label, content)` pairs, nearest
/// first — and return the first declaration. The first doc declaring a list
/// wins; lists are not merged. A doc declaring `auto` is circular and skipped.
/// A malformed declaration is an error for the caller (semi-auto reports it
/// and falls back to the default; a bad metadata line never fails a launch).
pub fn resolve_item_models<L, C>(
    docs: impl IntoIterator<Item = (L, Option<C>)>,
) -> Result<Option<DeclaredModels>>
where
    L: AsRef<str>,
    C: AsRef<str>,
{
    for (label, content) in docs {
        let Some(content) = content else { continue };
        let content = content.as_ref();
        let Some(field) = item_model_field(content) else {
            continue;
        };
        match parse_declaration(field).with_context(|| format!("declared by {}", label.as_ref()))? {
            Declaration::Auto => continue,
            Declaration::List(list) => {
                return Ok(Some(DeclaredModels {
                    list,
                    origin: label.as_ref().to_string(),
                    field: field.to_string(),
                }));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed(spec: &str) -> ModelChoice {
        match parse_model_spec(spec).unwrap() {
            ModelSpec::Fixed(choice) => choice,
            ModelSpec::Auto => panic!("`{spec}` should not be auto"),
        }
    }

    // ---- comma lists (§6.4 syntax) -------------------------------------


    /// Review 042 G74-2: the one `<number>-*.md` among a listing, or an error
    /// naming every match when two docs claim the number.
    #[test]
    fn unique_numbered_fails_closed_on_two_docs_for_one_number() {
        let names = ["066-loop-self-extend.md", "067-wifi.md", "0660-other.md", "066-notes.txt"];
        assert_eq!(unique_numbered(names, "066"), Ok(Some("066-loop-self-extend.md")));
        assert_eq!(unique_numbered(names, "068"), Ok(None));
        let shadowed = ["066-loop-self-extend.md", "066-0.md"];
        let err = unique_numbered(shadowed, "066").unwrap_err();
        assert!(err.contains("066-0.md, 066-loop-self-extend.md"), "{err}");
    }
    #[test]
    fn a_comma_list_parses_in_order_with_per_entry_variants() {
        let list = match parse_declaration("reasoning, flash variant=high").unwrap() {
            Declaration::List(list) => list,
            Declaration::Auto => panic!("a list, not auto"),
        };
        let entries = list.entries();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0], fixed("reasoning"));
        assert_eq!(entries[1], fixed("flash variant=high"));
        assert_eq!(entries[1].variant.as_deref(), Some("high"));
        assert_eq!(list.first(), &entries[0]);
    }

    #[test]
    fn a_single_entry_line_is_a_one_entry_list() {
        // The legacy form must resolve exactly as before the comma grammar.
        let list = match parse_declaration("flash effort=low").unwrap() {
            Declaration::List(list) => list,
            Declaration::Auto => panic!("flash is not auto"),
        };
        assert_eq!(list.entries(), &[fixed("flash variant=low")]);

        let claude = match parse_declaration("claude").unwrap() {
            Declaration::List(list) => list,
            Declaration::Auto => panic!("claude is not auto"),
        };
        assert_eq!(claude.entries(), &[ModelChoice::claude()]);
    }

    #[test]
    fn a_lone_auto_is_a_declaration_of_nothing() {
        assert_eq!(parse_declaration("auto").unwrap(), Declaration::Auto);
        // `auto` in a list is circular and refused; so are empty entries.
        assert!(parse_declaration("auto, flash").is_err());
        assert!(parse_declaration("flash, auto").is_err());
        assert!(parse_declaration("reasoning,").is_err());
        assert!(parse_declaration("reasoning, , flash").is_err());
    }

    // ---- backend match --------------------------------------------------

    #[test]
    fn backend_match_runs_the_first_listed_model_the_backend_can_run() {
        // `claude` ↔ claude; everything else ↔ opencode.
        let mixed = match parse_declaration("reasoning, claude, flash").unwrap() {
            Declaration::List(list) => list,
            Declaration::Auto => panic!("a list"),
        };
        assert!(mixed.backend_can_run(Backend::Claude));
        assert!(mixed.backend_can_run(Backend::Opencode));
        assert_eq!(mixed.first_for_backend(Backend::Claude), Some(&ModelChoice::claude()));
        assert_eq!(mixed.first_for_backend(Backend::Opencode), Some(&fixed("reasoning")));

        // A list with no claude entry gates a claude member out.
        let opencode_only = match parse_declaration("flash, reasoning").unwrap() {
            Declaration::List(list) => list,
            Declaration::Auto => panic!("a list"),
        };
        assert!(!opencode_only.backend_can_run(Backend::Claude));
        assert_eq!(opencode_only.first_for_backend(Backend::Claude), None);
    }

    // ---- member defaults (§6.4) -----------------------------------------

    #[test]
    fn the_member_default_is_the_single_model_for_undeclared_work() {
        // claude member → claude.
        let claude = member_default(Backend::Claude, Some("deepseek/deepseek-v4-pro"), None);
        assert_eq!(claude.entries(), &[ModelChoice::claude()]);

        // opencode member with a roster model+variant → that model+variant.
        let with_roster = member_default(Backend::Opencode, Some("deepseek/deepseek-flash"), Some("high"));
        let mut expected = ModelChoice::opencode(DEEPSEEK_FLASH);
        expected.variant = Some("high".into());
        assert_eq!(with_roster.entries(), &[expected]);

        // opencode member with nothing on the roster → flash.
        let bare = member_default(Backend::Opencode, None, None);
        assert_eq!(bare.entries(), &[ModelChoice::opencode(DEEPSEEK_FLASH)]);
    }

    // ---- model_change (§6.4) --------------------------------------------

    #[test]
    fn model_change_allows_any_listed_model_and_variant_changes_within_it() {
        let allowed = match parse_declaration("flash, reasoning").unwrap() {
            Declaration::List(list) => list,
            Declaration::Auto => panic!("a list"),
        };

        // Any listed model, declared unit.
        assert!(validate_model_change(&allowed, &fixed("flash"), true).is_ok());
        assert!(validate_model_change(&allowed, &fixed("reasoning"), true).is_ok());
        // A variant change within an allowed model is free.
        assert!(validate_model_change(&allowed, &fixed("flash variant=high"), true).is_ok());
        // A listed claude model hands to the claude backend.
        let mixed = match parse_declaration("flash, claude").unwrap() {
            Declaration::List(list) => list,
            Declaration::Auto => panic!("a list"),
        };
        assert!(validate_model_change(&mixed, &ModelChoice::claude(), true).is_ok());
        // Not listed → refused.
        assert_eq!(
            validate_model_change(&allowed, &fixed("deepseek/deepseek-chat"), true),
            Err(ModelRuleError::NotAllowed)
        );
        // claude requested against an opencode-only list → refused.
        assert_eq!(
            validate_model_change(&allowed, &ModelChoice::claude(), true),
            Err(ModelRuleError::NotAllowed)
        );
    }

    #[test]
    fn model_change_on_an_undeclared_unit_refuses_everything() {
        let default = member_default(Backend::Opencode, None, None);
        // Even the default itself: an undeclared unit allows NO change.
        assert_eq!(
            validate_model_change(&default, &fixed("flash"), false),
            Err(ModelRuleError::NotAllowed)
        );
        assert_eq!(
            validate_model_change(&default, &fixed("flash variant=high"), false),
            Err(ModelRuleError::NotAllowed)
        );
        assert_eq!(
            validate_model_change(&default, &ModelChoice::claude(), false),
            Err(ModelRuleError::NotAllowed)
        );
    }

    // ---- the §6.7 subset rule -------------------------------------------

    #[test]
    fn a_slice_body_may_declare_only_a_subset_of_its_inheritance() {
        let inherited = match parse_declaration("flash, reasoning").unwrap() {
            Declaration::List(list) => list,
            Declaration::Auto => panic!("a list"),
        };

        // A subset (any order) is fine; a variant knob within an inherited
        // model is a subset, not an escalation.
        let subset = match parse_declaration("reasoning").unwrap() {
            Declaration::List(list) => list,
            Declaration::Auto => panic!("a list"),
        };
        assert!(validate_declared_subset(Some(&inherited), &subset).is_ok());
        let with_variant = match parse_declaration("flash variant=low").unwrap() {
            Declaration::List(list) => list,
            Declaration::Auto => panic!("a list"),
        };
        assert!(validate_declared_subset(Some(&inherited), &with_variant).is_ok());

        // A model the slice would not inherit → refused.
        let escalated = match parse_declaration("deepseek/deepseek-chat").unwrap() {
            Declaration::List(list) => list,
            Declaration::Auto => panic!("a list"),
        };
        assert_eq!(
            validate_declared_subset(Some(&inherited), &escalated),
            Err(ModelRuleError::NotAllowed)
        );

        // Inherited nothing ⇒ may declare nothing.
        assert_eq!(
            validate_declared_subset(None, &subset),
            Err(ModelRuleError::DeclaresWithoutInheritance)
        );
    }

    // ---- the resolution chain (§6.4) ------------------------------------

    #[test]
    fn the_chain_walks_slice_then_innermost_sub_then_the_milestone() {
        let root = std::env::temp_dir().join(format!(
            "sf-modelchain-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let m = root.join("growlight/backlog/milestones/m");
        std::fs::create_dir_all(m.join("slices")).unwrap();
        std::fs::write(m.join("slices/005-picker.md"), "").unwrap();
        std::fs::write(m.join("CLAUDE.md"), "").unwrap();
        std::fs::create_dir_all(m.join("subs/s1/slices")).unwrap();
        std::fs::write(m.join("subs/s1/slices/007-resolver.md"), "").unwrap();
        std::fs::write(m.join("subs/s1/CLAUDE.md"), "").unwrap();
        std::fs::create_dir_all(m.join("subs/s1/subs/s2/slices")).unwrap();
        std::fs::write(m.join("subs/s1/subs/s2/CLAUDE.md"), "").unwrap();

        // For a top-level milestone slice: [slice doc, milestone CLAUDE.md].
        let direct = item_doc_candidates(&root, "m", Some("005")).unwrap();
        assert_eq!(
            direct,
            vec![m.join("slices/005-picker.md"), m.join("CLAUDE.md")]
        );

        // For a slice under m/s1: [slice doc, m/subs/s1/CLAUDE.md, m/CLAUDE.md].
        let one_sub = item_doc_candidates(&root, "m/s1", Some("7")).unwrap();
        assert_eq!(
            one_sub,
            vec![
                m.join("subs/s1/slices/007-resolver.md"),
                m.join("subs/s1/CLAUDE.md"),
                m.join("CLAUDE.md"),
            ]
        );

        // Nested two deep, innermost first.
        let two_subs = item_doc_candidates(&root, "m/s1/s2", None).unwrap();
        assert_eq!(
            two_subs,
            vec![
                m.join("subs/s1/subs/s2/CLAUDE.md"),
                m.join("subs/s1/CLAUDE.md"),
                m.join("CLAUDE.md"),
            ]
        );

        // A task has just its doc.
        let tasks = root.join("growlight/backlog/tasks");
        std::fs::create_dir_all(&tasks).unwrap();
        std::fs::write(tasks.join("047-a-task.md"), "").unwrap();
        assert_eq!(
            item_doc_candidates(&root, "047", None).unwrap(),
            vec![tasks.join("047-a-task.md")]
        );

        // Review 042 G74-2: a second doc claiming a number is a shadow — the
        // lookup fails closed rather than trust whichever sorts first.
        std::fs::write(tasks.join("047-0.md"), "> Model: claude\n").unwrap();
        let err = item_doc_candidates(&root, "047", None).unwrap_err();
        assert!(err.contains("047-0.md") && err.contains("047-a-task.md"), "{err}");
        std::fs::write(m.join("slices/005-shadow.md"), "").unwrap();
        assert!(item_doc_candidates(&root, "m", Some("5")).is_err(), "a shadow slice doc");
        assert!(item_doc_candidates(&root, "m", None).is_ok(), "no slice asked, no slice read");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn the_first_declaring_doc_wins_and_lists_never_merge() {
        let docs = [
            ("005-slice.md", Some("> Model: reasoning, flash\n")),
            ("CLAUDE.md", Some("> Model: claude\n")),
        ];
        let resolved = resolve_item_models(docs).unwrap().unwrap();
        assert_eq!(resolved.origin, "005-slice.md");
        assert_eq!(resolved.field, "reasoning, flash");
        assert_eq!(resolved.list.entries().len(), 2);

        // A nearer doc declaring nothing passes the chain up.
        let chain = [
            ("005-slice.md", Some("# X\n> Last reviewed: 2026-10-12\n")),
            ("CLAUDE.md", Some("> Model: claude\n")),
        ];
        let resolved = resolve_item_models(chain).unwrap().unwrap();
        assert_eq!(resolved.origin, "CLAUDE.md");
        assert_eq!(resolved.list, ModelList::single(ModelChoice::claude()));

        // A nearer `auto` is skipped, not a declaration.
        let auto = [
            ("005-slice.md", Some("> Model: auto\n")),
            ("CLAUDE.md", Some("> Model: flash\n")),
        ];
        let resolved = resolve_item_models(auto).unwrap().unwrap();
        assert_eq!(resolved.origin, "CLAUDE.md");

        // Nothing anywhere → undeclared.
        assert_eq!(resolve_item_models([("a", Some("# none\n"))]).unwrap(), None);

        // A malformed declaration is an error carrying the declaring doc.
        let bad = resolve_item_models([("005-slice.md", Some("> Model: gpt-9\n"))]);
        assert!(bad.is_err());
        assert!(bad.unwrap_err().to_string().contains("005-slice.md"));
    }
}
