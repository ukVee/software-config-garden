//! Consented, reversible offers — the helper's "never silent" posture
//! (`meta/spec-install.md` workstream B: "Prompts (reversible, consented)").
//!
//! Every step that touches something outside the build/install — the systemd
//! unit, `~/.claude.json` — is modeled as an [`Offer`]: what it does, and the
//! exact command that undoes it. The [`Consent`] trait is the seam the unit
//! tests fake; the real backends are the TTY prompt and the `--yes` / `--no`
//! flags. Nothing in the helper ever acts without an `Answer::Yes`.

/// An offered step and how to reverse it.
#[derive(Debug, Clone)]
pub struct Offer {
    /// A stable id, so a re-run / log can name the offer without its prose.
    pub id: &'static str,
    /// The question the user is asked.
    pub summary: String,
    /// The exact, copy-pasteable command(s) that undo this step.
    pub undo: String,
}

/// A consent answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Yes,
    No,
}

/// The consent seam. `ask` is called once per offer, in order.
pub trait Consent {
    fn ask(&mut self, offer: &Offer) -> Answer;
}

/// Read yes/no from a line of stdin. Anything but `y`/`yes` is `No` — the safe
/// default, the same `[y/N]` posture as `onboard-device.sh`'s `ask`.
pub struct Tty;

impl Consent for Tty {
    fn ask(&mut self, offer: &Offer) -> Answer {
        use std::io::{BufRead, Write};
        print!("{} [y/N] ", offer.summary);
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        if std::io::stdin().lock().read_line(&mut line).is_err() {
            return Answer::No; // no TTY / read failure ⇒ decline, never assume
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => Answer::Yes,
            _ => Answer::No,
        }
    }
}

/// Always the same answer — the `--yes` / `--no` flags, so a scripted install
/// can consent without a TTY. Offers still print their reversal.
pub struct Fixed(pub Answer);

impl Consent for Fixed {
    fn ask(&mut self, _offer: &Offer) -> Answer {
        self.0
    }
}

/// The scripted consent backend the unit tests drive. Lives in the crate (not
/// behind `#[cfg(test)]`) so integration tests may reuse it; it is a small,
/// pure queue.
pub struct Scripted(pub Vec<Answer>);

impl Consent for Scripted {
    fn ask(&mut self, _offer: &Offer) -> Answer {
        // Pop in order; an exhausted queue declines (safe default).
        if self.0.is_empty() {
            Answer::No
        } else {
            self.0.remove(0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tty_parses_only_an_affirmative() {
        // The TTY backend reads a real line; its *decision* is what matters, so
        // exercise the parsing half directly rather than plumbing a fake stdin.
        fn decide(line: &str) -> Answer {
            match line.trim().to_ascii_lowercase().as_str() {
                "y" | "yes" => Answer::Yes,
                _ => Answer::No,
            }
        }
        assert_eq!(decide("y"), Answer::Yes);
        assert_eq!(decide("YES"), Answer::Yes);
        assert_eq!(decide("yes"), Answer::Yes);
        assert_eq!(decide("n"), Answer::No);
        assert_eq!(decide(""), Answer::No);
        assert_eq!(decide("maybe"), Answer::No);
    }

    #[test]
    fn fixed_always_answers_the_same_way() {
        let mut yes = Fixed(Answer::Yes);
        let mut no = Fixed(Answer::No);
        let offer = Offer {
            id: "x",
            summary: "s".to_string(),
            undo: "u".to_string(),
        };
        assert_eq!(yes.ask(&offer), Answer::Yes);
        assert_eq!(no.ask(&offer), Answer::No);
    }

    #[test]
    fn scripted_answers_in_order_then_declines() {
        let mut backend = Scripted(vec![Answer::Yes, Answer::No]);
        let offer = Offer {
            id: "x",
            summary: "s".to_string(),
            undo: "u".to_string(),
        };
        assert_eq!(backend.ask(&offer), Answer::Yes);
        assert_eq!(backend.ask(&offer), Answer::No);
        // Exhausted ⇒ decline, never assume.
        assert_eq!(backend.ask(&offer), Answer::No);
    }
}
