//! The converter's output is something the v2 scheduler can run on
//! (queue-v2-migrate slice 005): plan the softfig-ipc migrate fixture under its
//! answers file, write the files the apply writes, then `assemble` reads them
//! and `pick_v2` walks them. The keeperd apply e2e proves the commit; this
//! proves growlightd's half, which keeperd's tests can't reach.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use softfig_growlightd::assemble;
use softfig_growlightd::scheduler_v2::{pick_v2, Member, SkipReason, Unit};
use softfig_ipc::model_choice::Backend;
use softfig_ipc::queue_v2::migrate::{plan, read_legacy, Answers, LegacyFiles};
use softfig_ipc::queue_v2::{slices_file, QUEUE_ARCHIVE_FILE, QUEUE_FILE};

fn load(root: &Path, dir: &Path, into: &mut BTreeMap<String, String>) {
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            load(root, &path, into);
        } else {
            let key = path.strip_prefix(root).unwrap().to_str().unwrap().to_string();
            into.insert(key, fs::read_to_string(&path).unwrap());
        }
    }
}

fn write(garden: &Path, rel: &str, text: &str) {
    let path = garden.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, text).unwrap();
}

#[test]
fn a_migrated_fixture_assembles_and_picks() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("../softfig-ipc/tests/fixtures/migrate");
    let mut files = LegacyFiles::default();
    load(&fixture.join("garden"), &fixture.join("garden"), &mut files.garden);
    load(&fixture.join("batons"), &fixture.join("batons"), &mut files.batons);
    let answers: Answers = toml::from_str(&fs::read_to_string(fixture.join("answers.toml")).unwrap()).unwrap();
    let plan = plan(&read_legacy(&files).unwrap(), &answers, "2026-11-01T00:00:00Z");
    assert!(plan.applicable(), "the fixture answers settle every call: {:?}", plan.refusals);

    // The garden after the apply: the legacy docs, untouched, plus the v2 files.
    let garden = tempfile::tempdir().unwrap();
    for (rel, text) in &files.garden {
        write(garden.path(), rel, text);
    }
    write(garden.path(), QUEUE_FILE, &plan.queue.to_toml().unwrap());
    write(garden.path(), QUEUE_ARCHIVE_FILE, &plan.archive.to_toml().unwrap());
    for (milestone, slices) in &plan.slices {
        write(garden.path(), &slices_file(milestone), &slices.to_toml().unwrap());
    }

    let mut snapshot = assemble(garden.path()).expect("the v2 files validate").expect("queue.toml is present");
    let ids: Vec<_> = snapshot.entries.iter().map(|e| e.id.as_str()).collect();
    assert_eq!(
        ids,
        [
            "semi-auto-backend-seam",
            "069",
            "folder-grants",
            "roadeye-m2-daemon-core",
            "hover-view-sticky",
            "hover-view-player",
        ],
        "list order is default, then the registry",
    );
    assert!(snapshot.done_ids.contains("claude-login-pool-wiring"), "a done row is archived");
    for (milestone, _) in &plan.slices {
        assert!(snapshot.trees.contains_key(milestone), "{milestone} has a tree");
    }

    // Today's fixture holds everything: deferred and blocked entries are
    // ineligible, and `> Fleet: no` maps to a human-only hold.
    snapshot.now_unix = 1_793_491_200; // 2026-11-01T00:00:00Z
    let member = Member { id: "a".into(), backend: Backend::Claude, pin: None };
    let outcome = pick_v2(&snapshot, &member);
    assert_eq!(outcome.picked, None);
    let skips: Vec<_> = outcome.skips.iter().map(|s| (s.entry.as_str(), s.reason)).collect();
    assert_eq!(
        skips,
        [
            ("semi-auto-backend-seam", SkipReason::NotEligible),
            ("069", SkipReason::NotEligible),
            ("folder-grants", SkipReason::HumanOnly),
            ("roadeye-m2-daemon-core", SkipReason::HumanOnly),
            ("hover-view-sticky", SkipReason::NotEligible),
            ("hover-view-player", SkipReason::NotEligible),
        ],
    );

    // Release folder-grants to the fleet and the walk runs on its migrated
    // `slices.toml`: a queued milestone's first slice.
    snapshot.entries.iter_mut().find(|e| e.id == "folder-grants").unwrap().fleet = true;
    let picked = pick_v2(&snapshot, &member).picked.expect("folder-grants is workable");
    assert_eq!(picked.entry, "folder-grants");
    assert_eq!(picked.unit, Unit::Slice { milestone: "folder-grants".into(), slice: "001".into() });
}
