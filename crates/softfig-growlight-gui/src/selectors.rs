//! Pure **view-model selectors** (spec §11): derivations over the [`App`] panel
//! state that the deferred iced `view()` walks to lay out the observe panels. A
//! selector does the *filtering / joining / ordering* — it never formats a line
//! (that is [`crate::render`]) and never names a pixel or an iced type. Every
//! selector is a pure fn of `&App`, so the panels are provable without a window.
//!
//! The three observe panels (spec §11):
//! - the per-agent **thoughts** view → [`agent_thoughts`] (+ [`agents_with_thoughts`]
//!   for the tab set);
//! - the **lease/roster** "who holds what" → [`who_holds_what`];
//! - the **fleet status** rows → [`fleet_status_rows`].

use crate::state::{AgentRow, App, LeaseRow, ThoughtLine};

/// The per-agent **thoughts** view (spec §12): this agent's fragments in arrival
/// order (oldest→newest), bounded to the most recent `n` — the *display*
/// scrollback window over the already-[`MAX_THOUGHTS`](crate::state::MAX_THOUGHTS)-capped
/// feed. `n == 0` yields an empty window; an unknown agent yields no rows.
pub fn agent_thoughts<'a>(app: &'a App, agent: &str, n: usize) -> Vec<&'a ThoughtLine> {
    let mut all: Vec<&ThoughtLine> = app.thoughts.iter().filter(|t| t.agent == agent).collect();
    // Keep only the last `n`, preserving oldest→newest order.
    let start = all.len().saturating_sub(n);
    all.split_off(start)
}

/// The distinct agents that have produced thoughts, in first-seen order — the tab
/// set the per-agent thoughts panel offers.
pub fn agents_with_thoughts(app: &App) -> Vec<&str> {
    let mut seen: Vec<&str> = Vec::new();
    for t in &app.thoughts {
        if !seen.contains(&t.agent.as_str()) {
            seen.push(t.agent.as_str());
        }
    }
    seen
}

/// One roster agent joined with the leases it currently holds (spec §4c).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RosterEntry<'a> {
    /// The roster row.
    pub agent: &'a AgentRow,
    /// The leases this agent holds (`holder == agent.id`), in lease order.
    pub held: Vec<&'a LeaseRow>,
}

/// The **"who holds what"** panel (spec §4c): every roster agent joined with the
/// leases it holds, plus the leases held by no listed agent. Every lease in
/// [`App::leases`](crate::state::App::leases) appears exactly once across
/// `agents[*].held` and `free` — the two buckets partition the lease set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WhoHoldsWhat<'a> {
    /// Roster agents, each with the leases it holds.
    pub agents: Vec<RosterEntry<'a>>,
    /// Leases not attributed to any listed agent: free/waiting (a released lease
    /// has `holder == None`), or held by a holder who has left the roster.
    pub free: Vec<&'a LeaseRow>,
}

/// Build the roster⋈leases [`WhoHoldsWhat`] join.
pub fn who_holds_what(app: &App) -> WhoHoldsWhat<'_> {
    let agents = app
        .agents
        .iter()
        .map(|a| RosterEntry {
            agent: a,
            held: app
                .leases
                .iter()
                .filter(|l| l.holder.as_deref() == Some(a.id.as_str()))
                .collect(),
        })
        .collect();
    let free = app
        .leases
        .iter()
        .filter(|l| match l.holder.as_deref() {
            None => true,
            Some(h) => !app.agents.iter().any(|a| a.id.as_str() == h),
        })
        .collect();
    WhoHoldsWhat { agents, free }
}

/// The **fleet status** panel rows: the roster in a stable display order (by id),
/// independent of arrival order so the panel doesn't reshuffle as deltas land.
pub fn fleet_status_rows(app: &App) -> Vec<&AgentRow> {
    let mut rows: Vec<&AgentRow> = app.agents.iter().collect();
    rows.sort_by(|a, b| a.id.cmp(&b.id));
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::ThoughtLine;
    use softfig_ipc::growlightd::AgentDeltaKind;

    fn thought(agent: &str, text: &str) -> ThoughtLine {
        ThoughtLine {
            agent: agent.into(),
            kind: AgentDeltaKind::Assistant,
            text: text.into(),
        }
    }

    #[test]
    fn agent_thoughts_filters_by_agent_in_order_and_recent_bounds_the_window() {
        let mut app = App::default();
        // Interleave two agents; "a" gets 0,1,2,3 with "b"'s line in the middle.
        for (agent, text) in [
            ("a", "0"),
            ("a", "1"),
            ("b", "x"),
            ("a", "2"),
            ("a", "3"),
        ] {
            app.push_thought(thought(agent, text));
        }

        // Full window: only "a"'s lines, oldest→newest.
        let all: Vec<&str> = agent_thoughts(&app, "a", 100)
            .iter()
            .map(|t| t.text.as_str())
            .collect();
        assert_eq!(all, ["0", "1", "2", "3"]);

        // recent(n) keeps the last n, still oldest→newest.
        let recent: Vec<&str> = agent_thoughts(&app, "a", 2)
            .iter()
            .map(|t| t.text.as_str())
            .collect();
        assert_eq!(recent, ["2", "3"]);

        // Degenerate / unknown cases.
        assert!(agent_thoughts(&app, "a", 0).is_empty());
        assert!(agent_thoughts(&app, "nobody", 5).is_empty());
    }

    #[test]
    fn agents_with_thoughts_is_distinct_first_seen_order() {
        let mut app = App::default();
        for (agent, text) in [("a", "0"), ("b", "0"), ("a", "1"), ("c", "0")] {
            app.push_thought(thought(agent, text));
        }
        assert_eq!(agents_with_thoughts(&app), ["a", "b", "c"]);
    }

    #[test]
    fn who_holds_what_joins_leases_to_holders_and_partitions() {
        let mut app = App::default();
        app.touch_agent("a");
        app.touch_agent("b");
        app.upsert_lease("k1".into(), Some("a".into()), "granted".into());
        app.upsert_lease("k2".into(), Some("b".into()), "granted".into());
        app.upsert_lease("k3".into(), None, "waiting".into());
        // A lease held by an agent that never joined the roster.
        app.upsert_lease("k4".into(), Some("ghost".into()), "granted".into());

        let who = who_holds_what(&app);
        let held_of = |id: &str| -> Vec<String> {
            who.agents
                .iter()
                .find(|e| e.agent.id == id)
                .unwrap()
                .held
                .iter()
                .map(|l| l.lease.clone())
                .collect()
        };
        assert_eq!(held_of("a"), ["k1"]);
        assert_eq!(held_of("b"), ["k2"]);
        // Free = the unheld waiting lease + the orphan-held one (no roster row).
        let free: Vec<&str> = who.free.iter().map(|l| l.lease.as_str()).collect();
        assert_eq!(free, ["k3", "k4"]);

        // Partition invariant: every lease appears exactly once across the view.
        let total = who.agents.iter().map(|e| e.held.len()).sum::<usize>() + who.free.len();
        assert_eq!(total, app.leases.len());

        // Releasing k1 drops it off a's row and surfaces it as free.
        app.upsert_lease("k1".into(), None, "released".into());
        let who2 = who_holds_what(&app);
        assert!(held_of_in(&who2, "a").is_empty());
        assert!(who2.free.iter().any(|l| l.lease == "k1"));
    }

    fn held_of_in<'a>(w: &'a WhoHoldsWhat<'a>, id: &str) -> &'a [&'a LeaseRow] {
        &w.agents.iter().find(|e| e.agent.id == id).unwrap().held
    }

    #[test]
    fn fleet_status_rows_are_ordered_by_id_regardless_of_arrival() {
        let mut app = App::default();
        for id in ["z", "a", "m"] {
            app.touch_agent(id);
        }
        let ids: Vec<&str> = fleet_status_rows(&app).iter().map(|r| r.id.as_str()).collect();
        assert_eq!(ids, ["a", "m", "z"]);
    }
}
