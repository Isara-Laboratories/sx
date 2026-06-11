//! In-memory store of granted secrets.
//!
//! Secrets live here and nowhere else the agent can reach: read on demand,
//! held only until their TTL expires, and never serialized back over the wire.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use sx_proto::CaptureInfo;

/// One granted `.env` source and the values it provided.
struct Grant {
    /// Canonical absolute path the values came from (display/identity only).
    source: String,
    values: HashMap<String, String>,
    expires_at: Instant,
    /// When true, commands run against this file skip the per-command prompt.
    allow_all: bool,
}

/// A still-live grant: whether it is allow-all, plus its values.
pub struct LiveGrant {
    pub allow_all: bool,
    pub values: Vec<(String, String)>,
}

/// All active grants. Not `Clone`/`Serialize` on purpose.
#[derive(Default)]
pub struct State {
    grants: Vec<Grant>,
}

impl State {
    /// Drop any grants whose TTL has elapsed.
    fn purge_expired(&mut self) {
        let now = Instant::now();
        self.grants.retain(|c| c.expires_at > now);
    }

    /// Insert (or replace) the grant for `source`, expiring after `ttl`.
    pub fn add(
        &mut self,
        source: String,
        values: HashMap<String, String>,
        ttl: Duration,
        allow_all: bool,
    ) {
        self.purge_expired();
        self.grants.retain(|c| c.source != source);
        self.grants.push(Grant {
            source,
            values,
            expires_at: Instant::now() + ttl,
            allow_all,
        });
    }

    /// Upgrade a live grant to allow-all and refresh its TTL. Returns false if
    /// no live grant exists for `source`.
    pub fn set_allow_all(&mut self, source: &str, ttl: Duration) -> bool {
        self.purge_expired();
        if let Some(g) = self.grants.iter_mut().find(|c| c.source == source) {
            g.allow_all = true;
            g.expires_at = Instant::now() + ttl;
            true
        } else {
            false
        }
    }

    /// Remove a single source's grant, or all of them when `path` is `None`.
    /// Returns how many grants were removed.
    pub fn clear(&mut self, path: Option<&str>) -> usize {
        let before = self.grants.len();
        match path {
            Some(p) => self.grants.retain(|c| c.source != p),
            None => self.grants.clear(),
        }
        before - self.grants.len()
    }

    /// Return a still-live grant for `source`, or `None` if it is not granted
    /// (or its TTL has elapsed).
    pub fn live(&mut self, source: &str) -> Option<LiveGrant> {
        self.purge_expired();
        self.grants.iter().find(|c| c.source == source).map(|c| {
            let mut values: Vec<(String, String)> = c
                .values
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            values.sort_by(|a, b| a.0.cmp(&b.0));
            LiveGrant {
                allow_all: c.allow_all,
                values,
            }
        })
    }

    /// Snapshot of active grants, safe to hand to the agent (names only).
    pub fn info(&mut self) -> Vec<CaptureInfo> {
        self.purge_expired();
        let now = Instant::now();
        self.grants
            .iter()
            .map(|c| {
                let mut names: Vec<String> = c.values.keys().cloned().collect();
                names.sort();
                CaptureInfo {
                    source: c.source.clone(),
                    names,
                    expires_in_secs: c.expires_at.saturating_duration_since(now).as_secs(),
                    allow_all: c.allow_all,
                }
            })
            .collect()
    }
}
