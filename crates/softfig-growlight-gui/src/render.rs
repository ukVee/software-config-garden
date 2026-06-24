//! A pure render-model: text-shaped projections of the [`App`] view-model that
//! the deferred iced `view()` maps onto widgets. Keeping the *content* of each
//! panel here (separate from pixel layout) gives the view a tested form now —
//! the §7b deferred work is only turning these strings into iced `Element`s and
//! showing a window.

use softfig_ipc::growlightd::AgentDeltaKind;

use crate::state::{App, ChatLine, ConnState, LeaseRow, ThoughtLine};

/// A short tag for a thought fragment's kind.
pub fn delta_kind_label(kind: AgentDeltaKind) -> &'static str {
    match kind {
        AgentDeltaKind::Assistant => "say",
        AgentDeltaKind::ToolCall => "tool",
        AgentDeltaKind::Thinking => "think",
    }
}

/// A human label for the connection state (the GUI's status pill).
pub fn connection_label(conn: &ConnState) -> String {
    match conn {
        ConnState::Connecting => "connecting…".to_string(),
        ConnState::Connected => "connected".to_string(),
        ConnState::Reconnecting { attempt } => format!("reconnecting (try {attempt})"),
        ConnState::Lost => "disconnected".to_string(),
    }
}

/// The top status line: daemon state · connection · agent count · budgets ·
/// paused. Mirrors the CLI/statusline idiom so the eventual `view()` header has
/// ready content.
pub fn status_summary(app: &App) -> String {
    let mut parts = vec![
        format!(
            "growlightd {}",
            if app.state_label.is_empty() {
                "?"
            } else {
                &app.state_label
            }
        ),
        connection_label(&app.conn),
        format!("{} agent(s)", app.agents.len()),
    ];
    if let Some(p) = app.budgets.session_5h_pct {
        parts.push(format!("5h {p}%"));
    }
    if let Some(p) = app.budgets.session_7d_pct {
        parts.push(format!("7d {p}%"));
    }
    if app.paused {
        parts.push("paused".to_string());
    }
    parts.join(" · ")
}

/// One thoughts-feed line: `[agent] kind text`.
pub fn thought_line(t: &ThoughtLine) -> String {
    format!("[{}] {} {}", t.agent, delta_kind_label(t.kind), t.text)
}

/// One groupchat line: `from→to [kind] body`. An optimistic (not-yet-echoed)
/// human post is marked `…`; a confirmed alert is marked `!`.
pub fn chat_line(c: &ChatLine) -> String {
    let marker = if c.pending {
        "…"
    } else if c.is_alert() {
        "!"
    } else {
        ""
    };
    format!("{}{}→{} [{}] {}", marker, c.from, c.to, c.kind, c.body)
}

/// One roster/lease line: `lease state (holder)`.
pub fn lease_line(l: &LeaseRow) -> String {
    format!(
        "{} {} (holder {})",
        l.lease,
        l.state,
        l.holder.as_deref().unwrap_or("-")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::App;
    use softfig_ipc::growlightd::AgentDeltaKind;

    #[test]
    fn status_summary_reads_back_the_key_fields() {
        let mut app = App {
            state_label: "running".into(),
            conn: ConnState::Connected,
            paused: true,
            ..Default::default()
        };
        app.touch_agent("loop-1");
        app.budgets.session_5h_pct = Some(12);
        let s = status_summary(&app);
        assert!(s.contains("growlightd running"), "{s}");
        assert!(s.contains("connected"), "{s}");
        assert!(s.contains("1 agent(s)"), "{s}");
        assert!(s.contains("5h 12%"), "{s}");
        assert!(s.contains("paused"), "{s}");
    }

    #[test]
    fn reconnecting_label_shows_the_attempt() {
        assert_eq!(
            connection_label(&ConnState::Reconnecting { attempt: 3 }),
            "reconnecting (try 3)"
        );
    }

    #[test]
    fn thought_chat_and_lease_lines_render() {
        let t = ThoughtLine {
            agent: "loop-1".into(),
            kind: AgentDeltaKind::ToolCall,
            text: "edit(x)".into(),
        };
        assert_eq!(thought_line(&t), "[loop-1] tool edit(x)");

        let alert = ChatLine::confirmed("loop-2", "human", "alert", "blocked");
        assert_eq!(chat_line(&alert), "!loop-2→human [alert] blocked");

        // An optimistic human post renders with the pending marker.
        let pending = ChatLine::pending("human", "all", "info", "hi");
        assert_eq!(chat_line(&pending), "…human→all [info] hi");

        let lease = LeaseRow {
            lease: "k".into(),
            holder: None,
            state: "released".into(),
        };
        assert_eq!(lease_line(&lease), "k released (holder -)");
    }
}
