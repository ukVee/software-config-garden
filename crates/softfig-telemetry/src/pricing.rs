//! `config/pricing.toml` and the pure per-row cost derivation (spec §6).
//!
//! A capture point prices a row once, with [`PriceTable::price_row`], before
//! handing it to the [`Recorder`](crate::Recorder). The cost is stored on the
//! row, so a later price edit never rewrites history.
//!
//! ## The table
//!
//! One `[[model]]` row per `(provider, model)`, every price in USD per million
//! tokens:
//!
//! ```toml
//! [[model]]
//! provider = "anthropic"
//! model = "claude-opus-5-5"
//! input_per_mtok = 4.0
//! output_per_mtok = 20.0
//! cache_read_per_mtok = 0.20
//! cache_create_per_mtok = 5.0        # the 5-minute cache-write tier
//! cache_create_1h_per_mtok = 8.0     # optional; default cache_create_per_mtok
//! thinking_per_mtok = 20.0           # optional; default output_per_mtok
//! fast_mode_multiplier = 2.0         # optional; a fast row has no price without it
//! context_window = 1_000_000         # optional; informational
//! ```
//!
//! Two optional shapes cover the published prices that are not one flat rate:
//!
//! - **Prompt-length tiers.** A second row for the same model with
//!   `prompt_tokens_over = N` applies to a request whose prompt (input + cache
//!   reads + cache writes) is over `N` tokens. The applicable row with the
//!   highest threshold wins.
//! - **Peak hours.** `peak_hours_utc = [[1, 4], [6, 10]]` (half-open UTC hours,
//!   Monday–Friday) with `off_peak_multiplier = 0.5`: the row's prices are the
//!   peak rate, and a request outside every window pays them × the multiplier.
//!
//! ## Lookup
//!
//! The exact `(provider, model)` first. Then the model id with its variant
//! suffixes stripped: a trailing `[…]` tag (`claude-opus-5-5[1m]`), then a
//! trailing `-YYYYMMDD` snapshot date. Anything else is unpriced. A bare
//! longest-prefix match would price an unknown `claude-opus-5-7` as
//! `claude-opus-5`, and a wrong number is worse than a null one.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use serde::Deserialize;

use crate::row::{RequestRow, SettledFrom, Speed};

/// The price table's path, relative to the garden root.
pub const PRICING_FILE: &str = "config/pricing.toml";

#[derive(Debug, thiserror::Error)]
pub enum PricingError {
    #[error("reading {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parsing the price table: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("price table: {0}")]
    Invalid(String),
}

/// One `[[model]]` row. See the module docs for each field's meaning.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelPrice {
    pub provider: String,
    pub model: String,
    pub input_per_mtok: f64,
    pub output_per_mtok: f64,
    pub cache_read_per_mtok: f64,
    pub cache_create_per_mtok: f64,
    pub cache_create_1h_per_mtok: Option<f64>,
    pub thinking_per_mtok: Option<f64>,
    pub fast_mode_multiplier: Option<f64>,
    pub prompt_tokens_over: Option<u64>,
    #[serde(default)]
    pub peak_hours_utc: Vec<[u8; 2]>,
    pub off_peak_multiplier: Option<f64>,
    pub context_window: Option<u64>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PricingFile {
    #[serde(default)]
    model: Vec<ModelPrice>,
}

/// The parsed price table.
#[derive(Debug)]
pub struct PriceTable {
    models: Vec<ModelPrice>,
    /// `(provider, model)` pairs already journalled as unpriced, so a long run
    /// on an unknown model costs one line, not one per request.
    unpriced: Mutex<HashSet<(String, String)>>,
}

impl PriceTable {
    /// Parse and validate a price table.
    pub fn parse(text: &str) -> Result<Self, PricingError> {
        let file: PricingFile = toml::from_str(text)?;
        let mut seen = HashSet::new();
        for p in &file.model {
            validate(p)?;
            let key = (&p.provider, &p.model, p.prompt_tokens_over.unwrap_or(0));
            if !seen.insert(key) {
                return Err(PricingError::Invalid(format!(
                    "{}/{} is listed twice for the same prompt tier",
                    p.provider, p.model
                )));
            }
        }
        Ok(Self {
            models: file.model,
            unpriced: Mutex::new(HashSet::new()),
        })
    }

    /// Read `<garden_root>/config/pricing.toml`.
    pub fn load(garden_root: &Path) -> Result<Self, PricingError> {
        let path = garden_root.join(PRICING_FILE);
        let text =
            std::fs::read_to_string(&path).map_err(|source| PricingError::Read { path, source })?;
        Self::parse(&text)
    }

    /// The row's cost in USD, or `None` when the table has no price for it:
    /// an unknown model, or a fast-mode row on a model with no
    /// `fast_mode_multiplier`. A [`SettledFrom::Ledger`] remainder is never
    /// priced here, because its tokens are unsplit; it carries the ledger's own
    /// USD difference instead.
    pub fn cost(&self, row: &RequestRow) -> Option<f64> {
        if row.settled_from == SettledFrom::Ledger {
            return None;
        }
        let t = &row.tokens;
        let p = self.lookup(&row.provider, &row.model, prompt_tokens(row))?;

        let one_h = t.cache_creation_1h.min(t.cache_creation);
        let five_m = t.cache_creation - one_h;
        let usd = |tokens: u64, per_mtok: f64| tokens as f64 * per_mtok / 1_000_000.0;
        let base = usd(t.input, p.input_per_mtok)
            + usd(t.output, p.output_per_mtok)
            + usd(t.cache_read, p.cache_read_per_mtok)
            + usd(five_m, p.cache_create_per_mtok)
            + usd(
                one_h,
                p.cache_create_1h_per_mtok
                    .unwrap_or(p.cache_create_per_mtok),
            )
            + usd(
                t.thinking.unwrap_or(0),
                p.thinking_per_mtok.unwrap_or(p.output_per_mtok),
            );

        let fast = match row.speed {
            Some(Speed::Fast) => p.fast_mode_multiplier?,
            _ => 1.0,
        };
        let off_peak = match p.off_peak_multiplier {
            Some(m) if !is_peak(row.ts, &p.peak_hours_utc) => m,
            _ => 1.0,
        };
        Some(base * fast * off_peak)
    }

    /// Set `row.cost_usd` from [`cost`](Self::cost). A ledger row is left as
    /// it is. An unpriced row stores null, never 0, and its `(provider, model)`
    /// is journalled once per table.
    pub fn price_row(&self, row: &mut RequestRow) {
        if row.settled_from == SettledFrom::Ledger {
            return;
        }
        row.cost_usd = self.cost(row);
        if row.cost_usd.is_none() {
            let key = (row.provider.clone(), row.model.clone());
            let mut unpriced = self.unpriced.lock().unwrap_or_else(|e| e.into_inner());
            if unpriced.insert(key) {
                eprintln!(
                    "telemetry: no price for {}/{}{} in {PRICING_FILE}; cost_usd stored as null",
                    row.provider,
                    row.model,
                    if row.speed == Some(Speed::Fast) {
                        " (fast mode)"
                    } else {
                        ""
                    },
                );
            }
        }
    }

    fn lookup(&self, provider: &str, model: &str, prompt: u64) -> Option<&ModelPrice> {
        let find = |id: &str| {
            self.models
                .iter()
                .filter(|p| p.provider == provider && p.model == id)
                .filter(|p| p.prompt_tokens_over.is_none_or(|over| prompt > over))
                .max_by_key(|p| p.prompt_tokens_over.unwrap_or(0))
        };
        find(model).or_else(|| {
            let base = snapshot_base(model);
            if base == model { None } else { find(base) }
        })
    }
}

fn validate(p: &ModelPrice) -> Result<(), PricingError> {
    let bad = |what: &str| {
        Err(PricingError::Invalid(format!(
            "{}/{}: {what}",
            p.provider, p.model
        )))
    };
    if p.provider.is_empty() || p.model.is_empty() {
        return bad("provider and model must be non-empty");
    }
    let prices = [
        Some(p.input_per_mtok),
        Some(p.output_per_mtok),
        Some(p.cache_read_per_mtok),
        Some(p.cache_create_per_mtok),
        p.cache_create_1h_per_mtok,
        p.thinking_per_mtok,
    ];
    if prices
        .into_iter()
        .flatten()
        .any(|v| !v.is_finite() || v < 0.0)
    {
        return bad("every price must be a finite number >= 0");
    }
    let multipliers = [p.fast_mode_multiplier, p.off_peak_multiplier];
    if multipliers
        .into_iter()
        .flatten()
        .any(|v| !v.is_finite() || v <= 0.0)
    {
        return bad("every multiplier must be a finite number > 0");
    }
    if p.peak_hours_utc.is_empty() != p.off_peak_multiplier.is_none() {
        return bad("peak_hours_utc and off_peak_multiplier come together");
    }
    if p.peak_hours_utc
        .iter()
        .any(|&[start, end]| start >= end || end > 24)
    {
        return bad("each peak_hours_utc window is [start, end) with start < end <= 24");
    }
    Ok(())
}

/// Every input-side token the request sent: the prompt length the tiered
/// prices are keyed on.
fn prompt_tokens(row: &RequestRow) -> u64 {
    let t = &row.tokens;
    t.input
        .saturating_add(t.cache_read)
        .saturating_add(t.cache_creation)
}

/// Strip a trailing `[…]` tag, then a trailing `-YYYYMMDD` snapshot date.
fn snapshot_base(model: &str) -> &str {
    let untagged = model
        .strip_suffix(']')
        .and_then(|m| m.rfind('[').map(|i| &m[..i]))
        .unwrap_or(model);
    match untagged.rsplit_once('-') {
        Some((base, date)) if date.len() == 8 && date.bytes().all(|b| b.is_ascii_digit()) => base,
        _ => untagged,
    }
}

/// Whether unix time `ts` falls in a peak window: a weekday (UTC) and an hour
/// inside one of `windows`.
fn is_peak(ts: i64, windows: &[[u8; 2]]) -> bool {
    let days = ts.div_euclid(86_400);
    // 1970-01-01 was a Thursday: 0 = Monday … 6 = Sunday.
    let weekday = (days + 3).rem_euclid(7);
    let hour = ts.rem_euclid(86_400) / 3_600;
    weekday < 5
        && windows
            .iter()
            .any(|&[start, end]| i64::from(start) <= hour && hour < i64::from(end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::row::TokenCounts;
    use crate::store::tests::row;

    const TABLE: &str = r#"
[[model]]
provider = "anthropic"
model = "claude-opus-5-5"
input_per_mtok = 4.0
output_per_mtok = 20.0
cache_read_per_mtok = 0.20
cache_create_per_mtok = 5.0
cache_create_1h_per_mtok = 8.0
fast_mode_multiplier = 2.0
context_window = 1_000_000

[[model]]
provider = "anthropic"
model = "claude-opus-5"
input_per_mtok = 5.0
output_per_mtok = 25.0
cache_read_per_mtok = 0.50
cache_create_per_mtok = 6.25

[[model]]
provider = "anthropic"
model = "claude-haiku-5-5"
input_per_mtok = 0.10
output_per_mtok = 0.50
cache_read_per_mtok = 0.01
cache_create_per_mtok = 0.125

[[model]]
provider = "anthropic"
model = "claude-haiku-5-5"
prompt_tokens_over = 100_000
input_per_mtok = 0.50
output_per_mtok = 2.50
cache_read_per_mtok = 0.05
cache_create_per_mtok = 0.625

[[model]]
provider = "deepseek"
model = "deepseek-flash"
input_per_mtok = 0.30
output_per_mtok = 1.20
cache_read_per_mtok = 0.006
cache_create_per_mtok = 0.30
thinking_per_mtok = 1.20
peak_hours_utc = [[1, 4], [6, 10]]
off_peak_multiplier = 0.5
"#;

    // 2026-10-28 is a Wednesday; 2026-10-31 a Saturday.
    const WED_0200Z: i64 = 1_793_152_800;
    const WED_1200Z: i64 = 1_793_188_800;
    const SAT_0200Z: i64 = 1_793_412_000;

    fn table() -> PriceTable {
        PriceTable::parse(TABLE).unwrap()
    }

    fn priced(model: &str, tokens: TokenCounts) -> RequestRow {
        let mut r = row("s", "r", 0);
        r.model = model.into();
        r.tokens = tokens;
        r.speed = Some(Speed::Standard);
        r.cost_usd = None;
        r
    }

    /// Sets one token class on an empty count.
    type SetClass = fn(&mut TokenCounts);

    fn million(class: SetClass) -> TokenCounts {
        let mut t = TokenCounts::default();
        class(&mut t);
        t
    }

    fn assert_usd(got: Option<f64>, want: f64) {
        let got = got.expect("row should be priced");
        assert!((got - want).abs() < 1e-9, "cost {got} != {want}");
    }

    #[test]
    fn each_class_is_billed_at_its_own_price() {
        let t = table();
        let cases: [(SetClass, f64); 5] = [
            (|t| t.input = 1_000_000, 4.0),
            (|t| t.output = 1_000_000, 20.0),
            (|t| t.cache_read = 1_000_000, 0.20),
            (|t| t.cache_creation = 1_000_000, 5.0),
            // thinking with no thinking_per_mtok is billed as output
            (|t| t.thinking = Some(1_000_000), 20.0),
        ];
        for (class, want) in cases {
            assert_usd(t.cost(&priced("claude-opus-5-5", million(class))), want);
        }
    }

    #[test]
    fn the_formula_sums_every_class() {
        let tokens = TokenCounts {
            input: 1_000,
            output: 2_000,
            cache_read: 300_000,
            cache_creation: 40_000,
            cache_creation_1h: 10_000,
            thinking: Some(5_000),
        };
        // 1k×4 + 2k×20 + 300k×0.20 + 30k×5 (5m) + 10k×8 (1h) + 5k×20 (thinking)
        let want = (4_000.0 + 40_000.0 + 60_000.0 + 150_000.0 + 80_000.0 + 100_000.0) / 1e6;
        assert_usd(table().cost(&priced("claude-opus-5-5", tokens)), want);
    }

    #[test]
    fn the_1h_tier_falls_back_to_the_5m_price_and_is_clamped() {
        let t = table();
        let tokens = TokenCounts {
            cache_creation: 1_000_000,
            cache_creation_1h: 1_000_000,
            ..TokenCounts::default()
        };
        // claude-opus-5 has no 1h price in this table
        assert_usd(t.cost(&priced("claude-opus-5", tokens)), 6.25);
        // a 1h count larger than the total it is part of bills as the total
        let over = TokenCounts {
            cache_creation_1h: 9_000_000,
            ..tokens
        };
        assert_usd(t.cost(&priced("claude-opus-5-5", over)), 8.0);
    }

    #[test]
    fn fast_mode_multiplies_every_class_and_needs_a_multiplier() {
        let t = table();
        let mut r = priced(
            "claude-opus-5-5",
            TokenCounts {
                input: 1_000_000,
                cache_read: 1_000_000,
                ..TokenCounts::default()
            },
        );
        r.speed = Some(Speed::Fast);
        assert_usd(t.cost(&r), (4.0 + 0.20) * 2.0);
        r.model = "claude-opus-5".into();
        assert_eq!(t.cost(&r), None, "no fast price is no price");
    }

    #[test]
    fn lookup_strips_snapshot_dates_and_tags_but_never_guesses() {
        let t = table();
        let tokens = million(|t| t.input = 1_000_000);
        for id in [
            "claude-opus-5-5",
            "claude-opus-5-5-20261001",
            "claude-opus-5-5[1m]",
            "claude-opus-5-5-20261001[1m]",
        ] {
            assert_usd(t.cost(&priced(id, tokens)), 4.0);
        }
        for id in ["claude-opus-5-7", "claude-opus-5-5-2026", "claude-opus"] {
            assert_eq!(t.cost(&priced(id, tokens)), None, "{id} must stay unpriced");
        }
        let mut other_provider = priced("claude-opus-5-5", tokens);
        other_provider.provider = "bedrock".into();
        assert_eq!(t.cost(&other_provider), None);
    }

    #[test]
    fn a_prompt_over_the_threshold_pays_the_tier_price() {
        let t = table();
        let at = TokenCounts {
            input: 40_000,
            cache_read: 60_000,
            output: 1_000_000,
            ..TokenCounts::default()
        };
        assert_usd(
            t.cost(&priced("claude-haiku-5-5", at)),
            0.004 + 0.0006 + 0.50,
        );
        let over = TokenCounts {
            cache_creation: 1,
            ..at
        };
        assert_usd(
            t.cost(&priced("claude-haiku-5-5", over)),
            0.02 + 0.003 + 0.000_000_625 + 2.50,
        );
    }

    #[test]
    fn off_peak_hours_and_weekends_get_the_multiplier() {
        let t = table();
        let mut r = priced("deepseek-flash", million(|t| t.output = 1_000_000));
        r.provider = "deepseek".into();
        for (ts, want) in [(WED_0200Z, 1.20), (WED_1200Z, 0.60), (SAT_0200Z, 0.60)] {
            r.ts = ts;
            assert_usd(t.cost(&r), want);
        }
    }

    #[test]
    fn price_row_skips_ledger_rows_and_nulls_unknown_models_once() {
        let t = table();
        let mut ledger = priced("claude-opus-5-5", million(|t| t.input = 1_000_000));
        ledger.settled_from = SettledFrom::Ledger;
        ledger.cost_usd = Some(0.42);
        t.price_row(&mut ledger);
        assert_eq!(ledger.cost_usd, Some(0.42), "the ledger's own USD stands");

        let mut known = priced("claude-opus-5-5", million(|t| t.input = 1_000_000));
        t.price_row(&mut known);
        assert_usd(known.cost_usd, 4.0);

        for _ in 0..3 {
            let mut unknown = priced("claude-opus-9", million(|t| t.input = 1));
            unknown.cost_usd = Some(0.0);
            t.price_row(&mut unknown);
            assert_eq!(unknown.cost_usd, None, "unknown is null, never 0");
        }
        assert_eq!(t.unpriced.lock().unwrap().len(), 1, "journalled once");
    }

    #[test]
    fn bad_tables_are_refused() {
        let row = |extra: &str| {
            format!(
                "[[model]]\nprovider = \"p\"\nmodel = \"m\"\ninput_per_mtok = 1.0\n\
                 output_per_mtok = 1.0\ncache_read_per_mtok = 1.0\ncache_create_per_mtok = 1.0\n{extra}"
            )
        };
        let twice = format!("{}\n{}", row(""), row(""));
        for (text, why) in [
            (twice.as_str(), "duplicate row"),
            (&row("cache_creat_per_mtok = 1.0"), "unknown field"),
            (&row("thinking_per_mtok = -1.0"), "negative price"),
            (&row("fast_mode_multiplier = 0.0"), "zero multiplier"),
            (
                &row("off_peak_multiplier = 0.5"),
                "multiplier without hours",
            ),
            (
                &row("peak_hours_utc = [[4, 1]]\noff_peak_multiplier = 0.5"),
                "backwards window",
            ),
        ] {
            assert!(PriceTable::parse(text).is_err(), "{why} must be refused");
        }
        let tiers = format!("{}\n{}", row(""), row("prompt_tokens_over = 10"));
        assert!(
            PriceTable::parse(&tiers).is_ok(),
            "two tiers are not a duplicate"
        );
    }

    #[test]
    fn load_reads_the_garden_file() {
        let garden = tempfile::tempdir().unwrap();
        let missing = PriceTable::load(garden.path()).unwrap_err();
        assert!(matches!(missing, PricingError::Read { .. }));
        std::fs::create_dir(garden.path().join("config")).unwrap();
        std::fs::write(garden.path().join(PRICING_FILE), TABLE).unwrap();
        assert_eq!(PriceTable::load(garden.path()).unwrap().models.len(), 5);
    }

    /// Validates a real price table: `SOFTFIG_PRICING_TOML=<path> cargo test
    /// -p softfig-telemetry -- --ignored seeded_table_parses`. Run it after
    /// editing the garden's `config/pricing.toml`.
    #[test]
    #[ignore = "reads the file named by SOFTFIG_PRICING_TOML"]
    fn seeded_table_parses() {
        let path = std::env::var("SOFTFIG_PRICING_TOML").expect("set SOFTFIG_PRICING_TOML");
        let text = std::fs::read_to_string(path).unwrap();
        let t = PriceTable::parse(&text).unwrap();
        let tokens = million(|t| t.input = 1_000_000);
        for model in ["claude-opus-5-5", "claude-sonnet-5-5", "claude-fable-5-1"] {
            assert!(t.cost(&priced(model, tokens)).is_some(), "{model} unpriced");
        }
    }
}
