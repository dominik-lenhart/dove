//! Rejected logins per mailbox (PLAN A85). Some providers (iCloud) answer a login with `NO` for a few minutes when they
//! have trouble of their own, so one rejection is not proof of a wrong password. A rejection starts a streak; while it
//! runs, new logins for the mailbox pause (5, 10, then every 15 minutes) so a wrong password never turns into a burst
//! of attempts that could lock the provider account. Only when at least [`REAUTH_MIN_FAILURES`] logins were rejected
//! over at least [`REAUTH_AFTER_SECS`], with no successful login in between, is the mailbox `reauth_required`.
//!
//! State is in memory: a restart starts over, which delays a reauth by at most one more streak.

use std::collections::HashMap;
use std::sync::Mutex;

/// A streak must be at least this old before it means "wrong password".
pub const REAUTH_AFTER_SECS: i64 = 30 * 60;
/// ... and hold at least this many rejected logins.
pub const REAUTH_MIN_FAILURES: u32 = 3;
const PAUSE_STEP_SECS: i64 = 5 * 60;
const PAUSE_MAX_SECS: i64 = 15 * 60;

struct Streak {
    generation: i64,
    first_at: i64,
    failures: u32,
    retry_at: i64,
}

/// What a rejected login means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Not yet proof: no new login for this mailbox before `retry_at` (unix seconds).
    Pause { failures: u32, retry_at: i64 },
    /// The streak is long enough: mark the mailbox `reauth_required`. The streak is cleared.
    Reauth,
    /// The failure belongs to a credential generation older than the current streak's (a reconnect happened).
    Stale,
}

#[derive(Default)]
pub struct LoginGuard {
    streaks: Mutex<HashMap<String, Streak>>,
}

impl LoginGuard {
    /// Whether a new login for this credential generation must wait. Logged-in sessions are not affected.
    pub fn paused(&self, account_id: &str, generation: i64, now: i64) -> bool {
        self.streaks
            .lock()
            .expect("lock")
            .get(account_id)
            .is_some_and(|s| s.generation == generation && now < s.retry_at)
    }

    /// Records a rejected login and decides what it means.
    pub fn failed(&self, account_id: &str, generation: i64, now: i64) -> Verdict {
        let mut streaks = self.streaks.lock().expect("lock");
        let s = streaks.entry(account_id.to_string()).or_insert(Streak {
            generation,
            first_at: now,
            failures: 0,
            retry_at: 0,
        });
        if generation < s.generation {
            return Verdict::Stale;
        }
        if generation > s.generation {
            *s = Streak { generation, first_at: now, failures: 0, retry_at: 0 };
        }
        s.failures += 1;
        if s.failures >= REAUTH_MIN_FAILURES && now - s.first_at >= REAUTH_AFTER_SECS {
            streaks.remove(account_id);
            return Verdict::Reauth;
        }
        s.retry_at = now + (PAUSE_STEP_SECS * i64::from(s.failures)).min(PAUSE_MAX_SECS);
        Verdict::Pause { failures: s.failures, retry_at: s.retry_at }
    }

    /// A login succeeded: the password works, the streak ends.
    pub fn succeeded(&self, account_id: &str) {
        self.streaks.lock().expect("lock").remove(account_id);
    }

    /// Test builds only: moves the streak `secs` into the past (its start and its pause).
    #[cfg(any(test, feature = "testing"))]
    pub fn backdate_for_tests(&self, account_id: &str, secs: i64) {
        if let Some(s) = self.streaks.lock().expect("lock").get_mut(account_id) {
            s.first_at -= secs;
            s.retry_at -= secs;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: i64 = 1_000_000;

    #[test]
    fn one_rejection_pauses_and_does_not_mean_reauth() {
        let g = LoginGuard::default();
        assert_eq!(g.failed("a", 1, T), Verdict::Pause { failures: 1, retry_at: T + 300 });
        assert!(g.paused("a", 1, T));
        assert!(g.paused("a", 1, T + 299));
        assert!(!g.paused("a", 1, T + 300));
        // Other mailboxes and newer credentials are not paused.
        assert!(!g.paused("b", 1, T));
        assert!(!g.paused("a", 2, T));
    }

    #[test]
    fn pauses_grow_and_cap() {
        let g = LoginGuard::default();
        let pauses: Vec<i64> = (0..4)
            .map(|i| match g.failed("a", 1, T + i) {
                Verdict::Pause { retry_at, .. } => retry_at - (T + i),
                v => panic!("{v:?}"),
            })
            .collect();
        assert_eq!(pauses, [300, 600, 900, 900]);
    }

    #[test]
    fn reauth_needs_both_enough_failures_and_enough_time() {
        // Many rejections within a few minutes: still a pause.
        let g = LoginGuard::default();
        for i in 0..10 {
            assert!(matches!(g.failed("a", 1, T + i), Verdict::Pause { .. }));
        }
        // An old streak with too few rejections: still a pause.
        let g = LoginGuard::default();
        g.failed("a", 1, T);
        assert!(matches!(g.failed("a", 1, T + 3 * REAUTH_AFTER_SECS), Verdict::Pause { failures: 2, .. }));
        // The third rejection exactly at the threshold age: reauth, and the streak is gone.
        assert_eq!(g.failed("a", 1, T + REAUTH_AFTER_SECS), Verdict::Reauth);
        assert!(!g.paused("a", 1, T + REAUTH_AFTER_SECS));
        // One second short of the age: a pause.
        let g = LoginGuard::default();
        g.failed("a", 1, T);
        g.failed("a", 1, T + 1);
        assert!(matches!(g.failed("a", 1, T + REAUTH_AFTER_SECS - 1), Verdict::Pause { failures: 3, .. }));
    }

    #[test]
    fn a_successful_login_ends_the_streak() {
        let g = LoginGuard::default();
        g.failed("a", 1, T);
        g.failed("a", 1, T + 1);
        g.succeeded("a");
        assert!(!g.paused("a", 1, T + 2));
        assert_eq!(
            g.failed("a", 1, T + REAUTH_AFTER_SECS),
            Verdict::Pause { failures: 1, retry_at: T + REAUTH_AFTER_SECS + 300 }
        );
    }

    #[test]
    fn generations_fence_the_streak() {
        let g = LoginGuard::default();
        g.failed("a", 2, T);
        g.failed("a", 2, T + 1);
        // A late rejection of the old password counts for nothing.
        assert_eq!(g.failed("a", 1, T + REAUTH_AFTER_SECS), Verdict::Stale);
        assert!(g.paused("a", 2, T + 2));
        // A newer password starts its own streak.
        assert_eq!(
            g.failed("a", 3, T + REAUTH_AFTER_SECS),
            Verdict::Pause { failures: 1, retry_at: T + REAUTH_AFTER_SECS + 300 }
        );
        assert!(!g.paused("a", 2, T + REAUTH_AFTER_SECS));
    }
}
