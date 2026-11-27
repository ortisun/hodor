//! The keys of clients at their addresses, fetched through the guarded
//! outbound client and kept in this server's memory.
//!
//! See `docs/architecture/contexts/oauth.md`, "Keys at the client's
//! address", and Decision 0079.

use crate::domain::client::{Client, ClientId};
use crate::domain::key::ClientKey;
use crate::domain::key_set::{
    KEY_SET_ACCEPT, KEY_SET_TIME_LIMIT, KeptSet, KeySetStep, MAX_KEY_SET_BYTES, next_step,
    published_keys,
};
use hodor_kernel::{Clock, HttpClient, HttpRequest, TenantContext, TenantId, Timestamp};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};

/// The most clients whose sets one server keeps.
pub const MAX_KEPT_KEY_SETS: usize = 10_000;

type Kept = HashMap<(TenantId, ClientId), KeptSet>;

fn lock(kept: &Mutex<Kept>) -> MutexGuard<'_, Kept> {
    kept.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The keys clients publish at their addresses, their `jwks_uri`: fetched
/// when a signature of the client is checked, kept for the tenant, the
/// client and the address for an hour at most, and fetched again for a
/// key the kept set lacks, at most once a minute per client. One for the
/// server, shared by every endpoint that checks a client's signature.
#[derive(Clone)]
pub struct ClientKeySets {
    http: Arc<dyn HttpClient>,
    clock: Arc<dyn Clock>,
    kept: Arc<Mutex<Kept>>,
}

impl std::fmt::Debug for ClientKeySets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientKeySets").finish_non_exhaustive()
    }
}

impl ClientKeySets {
    /// Fetches through `http`, the guarded outbound client, which should
    /// read no more than [`MAX_KEY_SET_BYTES`] of an answer.
    #[must_use]
    pub fn new(http: Arc<dyn HttpClient>, clock: Arc<dyn Clock>) -> Self {
        Self {
            http,
            clock,
            kept: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// The keys to check `signed`, a JSON Web Token of `client` in
    /// `tenant`, with: those at the client's address, fetched first when
    /// nothing young enough is kept or `signed` names a key the kept set
    /// lacks, and the address was not asked in the last minute. A fetch
    /// that fails leaves what was kept.
    async fn at_address(
        &self,
        tenant: TenantId,
        client: ClientId,
        address: &str,
        signed: Option<&str>,
    ) -> Vec<ClientKey> {
        let now = self.clock.now();
        {
            let mut kept = lock(&self.kept);
            if let KeySetStep::Use(keys) =
                next_step(kept.get(&(tenant, client)), address, signed, now)
            {
                return keys;
            }
            // Counted before the fetch answers: requests that arrive
            // meanwhile check against what is kept.
            match kept.get_mut(&(tenant, client)) {
                Some(set) if set.address == address => set.asked_at = now,
                _ => {
                    make_room(&mut kept, now);
                    kept.insert((tenant, client), KeptSet::asked(address.to_owned(), now));
                }
            }
        }
        let fetched = self.fetch(address, now).await;
        let mut kept = lock(&self.kept);
        let Some(set) = kept
            .get_mut(&(tenant, client))
            .filter(|set| set.address == address)
        else {
            // Made room for others meanwhile: what was fetched is used
            // once, and not kept.
            return fetched.unwrap_or_default();
        };
        if let Some(keys) = fetched {
            set.keys = keys;
            set.fetched_at = Some(now);
        }
        set.usable(self.clock.now()).to_vec()
    }

    /// What the address answers, if it answers a set within the bounds.
    async fn fetch(&self, address: &str, now: Timestamp) -> Option<Vec<ClientKey>> {
        let request = HttpRequest::get(address)
            .header("accept", KEY_SET_ACCEPT)
            .within(KEY_SET_TIME_LIMIT);
        let response = self.http.send(request).await.ok()?;
        // A redirect is not followed: it is an answer that is not a set.
        if !response.is_success() || response.body.len() > MAX_KEY_SET_BYTES {
            return None;
        }
        published_keys(&response.body, now)
    }
}

/// Makes room for one more client when [`MAX_KEPT_KEY_SETS`] are kept:
/// the sets that may no longer be used, and were not asked for in the
/// last minute, go first; then the one asked for longest ago.
fn make_room(kept: &mut Kept, now: Timestamp) {
    if kept.len() < MAX_KEPT_KEY_SETS {
        return;
    }
    kept.retain(|_, set| set.is_fresh(now) || set.asked_lately(now));
    if kept.len() >= MAX_KEPT_KEY_SETS
        && let Some(oldest) = kept
            .iter()
            .min_by_key(|(_, set)| set.asked_at)
            .map(|(key, _)| *key)
    {
        kept.remove(&oldest);
    }
}

/// The keys to check `signed`, a JSON Web Token of `client` in `tenant`,
/// with: those Hodor keeps for the client, or, for a client with a key set
/// address, those at it, through `sets`. Without `sets`, a client with an
/// address has no keys.
pub(crate) async fn keys_of(
    sets: Option<&ClientKeySets>,
    tenant: &TenantContext,
    client: &Client,
    signed: Option<&str>,
) -> Vec<ClientKey> {
    match (client.jwks_uri(), sets) {
        (None, _) => client.snapshot().keys.clone(),
        (Some(address), Some(sets)) => {
            sets.at_address(tenant.tenant_id(), client.id(), address, signed)
                .await
        }
        (Some(_), None) => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::key_set::KEY_SET_KEPT_FOR;

    fn set(asked_at: Timestamp, fetched_at: Option<Timestamp>) -> KeptSet {
        KeptSet {
            address: "https://payroll.example.com/jwks".to_owned(),
            keys: Vec::new(),
            fetched_at,
            asked_at,
        }
    }

    #[test]
    fn room_is_made_from_the_sets_that_can_no_longer_be_used_then_the_oldest() {
        let now = Timestamp::UNIX_EPOCH + KEY_SET_KEPT_FOR * 10;
        let tenant = TenantId::generate();
        let mut kept = Kept::new();
        let mut stale = None;
        for n in 0..MAX_KEPT_KEY_SETS {
            let client = ClientId::generate();
            let at = now - time::Duration::minutes(2) - time::Duration::seconds(n as i64 % 600);
            // One set of ten is past its hour.
            let entry = if n % 10 == 0 {
                stale = Some(client);
                set(at, Some(now - KEY_SET_KEPT_FOR * 2))
            } else {
                set(at, Some(at))
            };
            kept.insert((tenant, client), entry);
        }
        make_room(&mut kept, now);
        assert_eq!(kept.len(), MAX_KEPT_KEY_SETS - MAX_KEPT_KEY_SETS / 10);
        assert!(!kept.contains_key(&(tenant, stale.expect("a stale set"))));

        // When every set may still be used, the one asked for longest ago
        // goes.
        let mut full = Kept::new();
        let mut oldest = None;
        for n in 0..MAX_KEPT_KEY_SETS {
            let client = ClientId::generate();
            let at = now - time::Duration::seconds(n as i64 % 50);
            if n == 7 {
                oldest = Some(client);
            }
            let at = if n == 7 {
                now - time::Duration::minutes(30)
            } else {
                at
            };
            full.insert((tenant, client), set(at, Some(at)));
        }
        make_room(&mut full, now);
        assert_eq!(full.len(), MAX_KEPT_KEY_SETS - 1);
        assert!(!full.contains_key(&(tenant, oldest.expect("the oldest"))));
    }
}
