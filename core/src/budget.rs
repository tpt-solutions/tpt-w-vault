// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Write budget for the content key: counts block writes against the limits in
//! `docs/crypto.md` ("Nonce budget").
//!
//! Every block write uses a fresh random nonce under the content key, so the count must survive
//! restarts. It is stored in `vault.conf` as a *ceiling*: the real count never exceeds the stored
//! value. The ceiling is raised by a chunk before writes pass it, and that write to `vault.conf`
//! is synced first. After a restart the count starts at the stored ceiling. That can over-count
//! by up to one chunk, but it never under-counts, so the limits hold across crashes.

use std::{
    path::PathBuf,
    sync::{Arc, Mutex, MutexGuard},
};

use crate::config::VaultConfig;
use crate::error::{Result, VaultError};

/// Limits on block writes under one content key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limits {
    /// At or above this count the vault asks for a re-key.
    pub soft: u64,
    /// At or above this count writes are refused until the vault is re-keyed.
    pub hard: u64,
    /// How far the stored ceiling moves each time it is raised.
    pub chunk: u64,
}

impl Limits {
    /// The policy in `docs/crypto.md`: soft 2^31, hard 2^32.
    pub(crate) const POLICY: Limits = Limits {
        soft: 1 << 31,
        hard: 1 << 32,
        chunk: 1 << 20,
    };
}

/// Where a vault stands against the write limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetStatus {
    /// Block writes counted so far. Can be a little above the true count after a restart.
    pub writes: u64,
    /// The soft limit has been reached: a re-key is recommended.
    pub soft_reached: bool,
    /// The hard limit has been reached: writes are refused until the vault is re-keyed.
    pub hard_reached: bool,
}

/// Counter shared by every open file in one unlocked vault session.
pub(crate) struct WriteBudget {
    conf: PathBuf,
    limits: Limits,
    /// Serializes changes to `vault.conf` with the other config updates in this session.
    conf_lock: Arc<Mutex<()>>,
    state: Mutex<State>,
}

struct State {
    used: u64,
    ceiling: u64,
}

impl WriteBudget {
    /// Starts counting from `ceiling`, the value stored in `vault.conf` when the session opened.
    pub(crate) fn new(
        conf: PathBuf,
        ceiling: u64,
        limits: Limits,
        conf_lock: Arc<Mutex<()>>,
    ) -> Self {
        WriteBudget {
            conf,
            limits,
            conf_lock,
            state: Mutex::new(State {
                used: ceiling,
                ceiling,
            }),
        }
    }

    /// Counts one block write. Refuses it once the hard limit is reached. Persists a new ceiling
    /// before the count goes past the stored one.
    pub(crate) fn take(&self) -> Result<()> {
        let mut state = lock(&self.state);
        if state.used >= self.limits.hard {
            return Err(VaultError::WriteLimitReached);
        }
        if state.used >= state.ceiling {
            let next = state
                .used
                .saturating_add(self.limits.chunk)
                .min(self.limits.hard);
            {
                let _conf = lock(&self.conf_lock);
                VaultConfig::store_write_ceiling(&self.conf, next)?;
            }
            state.ceiling = next;
        }
        state.used += 1;
        Ok(())
    }

    pub(crate) fn status(&self) -> BudgetStatus {
        let used = lock(&self.state).used;
        BudgetStatus {
            writes: used,
            soft_reached: used >= self.limits.soft,
            hard_reached: used >= self.limits.hard,
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A panic while holding the lock leaves plain counters behind, which are still valid.
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::KdfParams;

    const SMALL: Limits = Limits {
        soft: 3,
        hard: 5,
        chunk: 2,
    };

    fn conf_file() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("vault.conf");
        let (config, _master) = VaultConfig::create(
            b"budget-test",
            KdfParams {
                log_n: 10,
                r: 8,
                p: 1,
            },
        )
        .unwrap();
        config.save_atomic(&path).unwrap();
        (dir, path)
    }

    fn budget(path: &std::path::Path, ceiling: u64, limits: Limits) -> WriteBudget {
        WriteBudget::new(
            path.to_path_buf(),
            ceiling,
            limits,
            Arc::new(Mutex::new(())),
        )
    }

    #[test]
    fn writes_are_refused_at_the_hard_limit() {
        let (_dir, path) = conf_file();
        let b = budget(&path, 0, SMALL);
        for _ in 0..5 {
            b.take().unwrap();
        }
        assert!(matches!(b.take(), Err(VaultError::WriteLimitReached)));
        let s = b.status();
        assert_eq!(s.writes, 5);
        assert!(s.soft_reached && s.hard_reached);
    }

    #[test]
    fn soft_limit_is_reported_before_the_hard_limit() {
        let (_dir, path) = conf_file();
        let b = budget(&path, 0, SMALL);
        for _ in 0..2 {
            b.take().unwrap();
        }
        assert!(!b.status().soft_reached);
        b.take().unwrap();
        let s = b.status();
        assert!(s.soft_reached);
        assert!(!s.hard_reached);
    }

    #[test]
    fn the_stored_ceiling_is_never_below_the_count() {
        let (_dir, path) = conf_file();
        let b = budget(&path, 0, SMALL);
        for _ in 0..3 {
            b.take().unwrap();
        }
        // Three writes used a chunk of two, so the stored ceiling is four.
        let stored = VaultConfig::load(&path).unwrap().write_ceiling;
        assert!(stored >= 3, "stored ceiling {stored} is below the count");

        // A restart starts from the stored value, so the count is never lower than before.
        let reopened = budget(&path, stored, SMALL);
        assert!(reopened.status().writes >= 3);
    }

    #[test]
    fn restart_cannot_reset_the_count_below_the_stored_ceiling() {
        let (_dir, path) = conf_file();
        let b = budget(&path, 0, SMALL);
        for _ in 0..4 {
            b.take().unwrap();
        }
        let stored = VaultConfig::load(&path).unwrap().write_ceiling;
        let reopened = budget(&path, stored, SMALL);
        // Only one write is left before the hard limit of five, however many were made before.
        reopened.take().unwrap();
        assert!(matches!(
            reopened.take(),
            Err(VaultError::WriteLimitReached)
        ));
    }
}
