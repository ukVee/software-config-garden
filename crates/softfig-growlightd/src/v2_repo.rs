//! The v2 **repo resolver** (queue-v2-parity slice 005): the local repo a v2
//! entry's work lands in, for the boot dirty-tree guard (parity row 6) and the
//! spin guard's repo progress (row 7) — the v2 twin of the legacy
//! [`item_repo_path`](softfig_ipc::item_repo::item_repo_path) lookup.
//!
//! It reads the entry's project from the [`V2Snapshot`] and trusts the
//! `locality` the v2 source stamped (slice 004, report 062): only a
//! [`RepoLocality::Local`] repo resolves. A remote or ambiguous one gives
//! `None` — no repo signal, exactly as legacy gives none for a repo this
//! machine cannot probe. The `~` forms expand through the one shared expander,
//! [`expand_home`], with the current user so `~<user>/…` (which the classifier
//! calls local) resolves too.

use std::path::{Path, PathBuf};

use softfig_ipc::item_repo::expand_home;
use softfig_ipc::queue_v2::RepoLocality;

use crate::scheduler_v2::{project_of, ProjectView, V2Snapshot};

/// The project `entry` belongs to in `snapshot`. `entry` is a pick's milestone
/// identity, so a sub-milestone's `"<parent>/<sub>"` joins on its top-level
/// entry, which owns the project (§3.3).
pub fn entry_project<'a>(snapshot: &'a V2Snapshot, entry: &str) -> Option<&'a ProjectView> {
    let top = entry.split('/').next().unwrap_or(entry);
    project_of(snapshot, snapshot.entries.iter().find(|e| e.id == top)?)
}

/// `project`'s repo as a local path, or `None` unless it is
/// [`RepoLocality::Local`]. `home` / `user` are what `~` and `~<user>` expand
/// against (`$HOME` / `$USER`).
pub fn local_repo(project: &ProjectView, home: Option<&Path>, user: Option<&str>) -> Option<PathBuf> {
    if project.locality != RepoLocality::Local {
        return None;
    }
    expand_home(project.repo.trim(), home, user)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scheduler_v2::EntryView;
    use softfig_ipc::queue_v2::{EntryKind, EntryStatus, Lane};

    fn project(repo: &str) -> ProjectView {
        ProjectView {
            name: "p".into(),
            repo: repo.into(),
            locality: RepoLocality::of(repo, Some("u")),
            main: "main".into(),
        }
    }

    fn resolve(repo: &str) -> Option<PathBuf> {
        local_repo(&project(repo), Some(Path::new("/home/u")), Some("u"))
    }

    #[test]
    fn an_absolute_repo_resolves_as_written() {
        assert_eq!(resolve("/srv/r"), Some(PathBuf::from("/srv/r")));
        assert_eq!(resolve("/srv/a:b"), Some(PathBuf::from("/srv/a:b")), "a `:` in a local path");
    }

    #[test]
    fn a_bare_tilde_resolves_to_home() {
        assert_eq!(resolve("~"), Some(PathBuf::from("/home/u")));
    }

    #[test]
    fn a_tilde_slash_repo_resolves_under_home() {
        assert_eq!(resolve("~/projects/r"), Some(PathBuf::from("/home/u/projects/r")));
    }

    #[test]
    fn the_current_users_tilde_resolves_under_home() {
        assert_eq!(resolve("~u/projects/r"), Some(PathBuf::from("/home/u/projects/r")));
    }

    #[test]
    fn a_remote_repo_gives_no_signal() {
        assert_eq!(project("host:/srv/r").locality, RepoLocality::Remote);
        assert_eq!(resolve("host:/srv/r"), None);
    }

    #[test]
    fn an_ambiguous_repo_gives_no_signal() {
        for repo in ["~bob/r", "projects/r", ":r"] {
            assert_eq!(project(repo).locality, RepoLocality::Ambiguous, "{repo}");
            assert_eq!(resolve(repo), None, "{repo}");
        }
    }

    #[test]
    fn a_sub_milestone_joins_on_its_top_level_entry() {
        let mut snapshot = V2Snapshot::default();
        snapshot.projects.push(project("/srv/r"));
        snapshot.entries.push(EntryView {
            id: "m1".into(),
            kind: EntryKind::Milestone,
            project: "p".into(),
            lane: Lane::Normal,
            status: EntryStatus::Active,
            after: vec![],
            branch: String::new(),
            claimed: String::new(),
            parent: String::new(),
            base: String::new(),
            follow_ups: 0,
            pending: None,
            fleet: true,
            not_before: None,
            auto_restack: true,
            holder: None,
            models: None,
        });
        assert_eq!(entry_project(&snapshot, "m1").map(|p| p.repo.as_str()), Some("/srv/r"));
        assert_eq!(entry_project(&snapshot, "m1/sub").map(|p| p.repo.as_str()), Some("/srv/r"));
        assert_eq!(entry_project(&snapshot, "m2"), None);
    }
}
