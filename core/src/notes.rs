// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (c) 2026 TPT Solutions

//! Note storage and autosave timing for the secure markdown editor (Phase 7).
//!
//! Notes are ordinary vault files, so they get the same encryption as every other entry. The
//! editor never writes plaintext to a temp file. [`Autosave`] decides when a pending edit should
//! be saved, and it takes the clock as an argument, so tests do not depend on real time.

use std::time::{Duration, Instant};

use crate::backend::{VaultBackend, VaultFile};
use crate::error::Result;

/// Default quiet period after the last keystroke before a save.
pub const DEFAULT_DEBOUNCE: Duration = Duration::from_millis(1500);
/// Longest time an edit may stay unsaved while the user keeps typing.
pub const DEFAULT_MAX_WAIT: Duration = Duration::from_secs(10);

/// Debounced autosave timing.
///
/// A save becomes due once the user has paused for `debounce`, or once the first unsaved edit
/// is `max_wait` old. The second rule stops a user who types without pausing from never saving.
#[derive(Debug, Clone)]
pub struct Autosave {
    debounce: Duration,
    max_wait: Duration,
    first_unsaved: Option<Instant>,
    last_edit: Option<Instant>,
}

impl Default for Autosave {
    fn default() -> Self {
        Autosave::new(DEFAULT_DEBOUNCE, DEFAULT_MAX_WAIT)
    }
}

impl Autosave {
    pub fn new(debounce: Duration, max_wait: Duration) -> Self {
        Autosave {
            debounce,
            max_wait,
            first_unsaved: None,
            last_edit: None,
        }
    }

    /// Records an edit at `now`.
    pub fn edited(&mut self, now: Instant) {
        self.first_unsaved.get_or_insert(now);
        self.last_edit = Some(now);
    }

    /// Whether unsaved edits exist.
    pub fn is_dirty(&self) -> bool {
        self.first_unsaved.is_some()
    }

    /// Whether a save should happen at `now`.
    pub fn due(&self, now: Instant) -> bool {
        match (self.first_unsaved, self.last_edit) {
            (Some(first), Some(last)) => {
                now.saturating_duration_since(last) >= self.debounce
                    || now.saturating_duration_since(first) >= self.max_wait
            }
            _ => false,
        }
    }

    /// Clears the dirty state after a successful save.
    pub fn saved(&mut self) {
        self.first_unsaved = None;
        self.last_edit = None;
    }
}

/// Replaces the contents of the note at `path` with `text`, creating the note if needed.
///
/// The write goes over the existing bytes and then truncates, so a shorter note never keeps
/// the tail of an older, longer version.
pub fn save_note<B: VaultBackend>(backend: &B, path: &str, text: &str) -> Result<()> {
    let mut file = match backend.open_file(path) {
        Ok(f) => f,
        Err(crate::error::VaultError::NotFound(_)) => backend.create_file(path)?,
        Err(e) => return Err(e),
    };
    let bytes = text.as_bytes();
    file.write_at(0, bytes)?;
    file.truncate(bytes.len() as u64)
}

/// Reads the note at `path` as UTF-8 text.
pub fn load_note<B: VaultBackend>(backend: &B, path: &str) -> Result<String> {
    let mut file = backend.open_file(path)?;
    let len = file.size()? as usize;
    let mut buf = vec![0u8; len];
    let mut done = 0;
    while done < len {
        let n = file.read_at(done as u64, &mut buf[done..])?;
        if n == 0 {
            break;
        }
        done += n;
    }
    buf.truncate(done);
    String::from_utf8(buf).map_err(|_| crate::error::VaultError::Corrupt {
        path: path.to_owned(),
        detail: "note is not valid UTF-8".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nothing_is_due_without_an_edit() {
        let a = Autosave::default();
        assert!(!a.is_dirty());
        assert!(!a.due(Instant::now() + Duration::from_secs(60)));
    }

    #[test]
    fn saves_after_a_pause() {
        let mut a = Autosave::new(Duration::from_millis(500), Duration::from_secs(10));
        let t0 = Instant::now();
        a.edited(t0);
        assert!(!a.due(t0 + Duration::from_millis(499)));
        assert!(a.due(t0 + Duration::from_millis(500)));
    }

    #[test]
    fn each_keystroke_restarts_the_quiet_period() {
        let mut a = Autosave::new(Duration::from_millis(500), Duration::from_secs(10));
        let t0 = Instant::now();
        a.edited(t0);
        a.edited(t0 + Duration::from_millis(400));
        assert!(
            !a.due(t0 + Duration::from_millis(800)),
            "pause measured from last edit"
        );
        assert!(a.due(t0 + Duration::from_millis(900)));
    }

    #[test]
    fn continuous_typing_still_saves_at_max_wait() {
        let mut a = Autosave::new(Duration::from_millis(500), Duration::from_secs(2));
        let t0 = Instant::now();
        // An edit every 100 ms never leaves a 500 ms gap, so only max_wait can trigger a save.
        for i in 0..19 {
            a.edited(t0 + Duration::from_millis(100 * i));
            assert!(!a.due(t0 + Duration::from_millis(100 * i)));
        }
        assert!(a.due(t0 + Duration::from_secs(2)));
    }

    #[test]
    fn saved_clears_the_dirty_state() {
        let mut a = Autosave::default();
        let t0 = Instant::now();
        a.edited(t0);
        a.saved();
        assert!(!a.is_dirty());
        assert!(!a.due(t0 + Duration::from_secs(60)));
    }
}
