//! The deploy table — the `bombadil.toml` `[settings.dots]` analog, living
//! in the garden at `config/deploy.toml`. M4a parses the minimal schema: a
//! `[dots]` table of `name = { source, target, method? }`. Var / profile /
//! posthook keys are intentionally absent here — they arrive with M4b/M4c.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use crate::{DeployError, Result};

/// The parsed `config/deploy.toml`.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployConfig {
    /// Named source→target entries. A `BTreeMap` so iteration order — and
    /// therefore the plan/report order — is stable (by name).
    #[serde(default)]
    pub dots: BTreeMap<String, Dot>,
}

/// One deploy entry. `source` is relative to `config/source/`; `target` is
/// `$HOME`-relative (or absolute-under-`$HOME`).
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Dot {
    pub source: String,
    pub target: String,
    #[serde(default)]
    pub method: Method,
}

/// How a dot reaches its target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Method {
    /// Materialize the source into the deploy-cache, symlink the target → it
    /// (default; survives garden lock).
    #[default]
    Symlink,
    /// Write the bytes straight to the target with a managed-by stamp (for
    /// apps that reject symlinked configs).
    Copy,
}

impl DeployConfig {
    /// Parse a `deploy.toml` body.
    pub fn parse(toml_src: &str) -> Result<Self> {
        toml::from_str(toml_src).map_err(|e| DeployError::ConfigParse(e.to_string()))
    }

    /// Load + parse the config file. A missing file maps to
    /// [`DeployError::ConfigNotFound`] (the "is the garden unlocked?" case),
    /// distinct from a parse error.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(src) => Self::parse(&src),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(DeployError::ConfigNotFound(path.to_path_buf()))
            }
            Err(e) => Err(e.into()),
        }
    }
}
