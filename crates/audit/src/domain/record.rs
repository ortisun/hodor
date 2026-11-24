//! An audit record and the chain it is a link of.

use hodor_kernel::{Actor, CorrelationId, Digest, EventEnvelope, EventId, TenantId, Timestamp};
use serde_json::Value;

/// What every hash starts with, so that a hash of this kind can never be
/// mistaken for a hash of anything else, and so that the rules can change
/// under a new name.
const DOMAIN: &[u8] = b"hodor.audit.v1";

/// The end of a tenant's chain: the last record's sequence and hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChainHead {
    /// The last record's sequence; 0 before the first record.
    pub sequence: u64,
    /// The last record's hash; zeros before the first record.
    pub hash: [u8; 32],
}

impl ChainHead {
    /// The head of a chain with no records.
    pub const EMPTY: Self = Self {
        sequence: 0,
        hash: [0; 32],
    };
}

/// One thing that happened, as it is kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// The record's position in its tenant's chain, starting at 1.
    pub sequence: u64,
    /// The event the record was made from.
    pub event_id: EventId,
    /// The event's type, for example `authentication.succeeded`.
    pub action: String,
    /// When the change happened.
    pub occurred_at: Timestamp,
    /// When the record was appended. Not covered by the hash.
    pub recorded_at: Timestamp,
    /// Who caused it.
    pub actor: Actor,
    /// The request or job that caused it.
    pub correlation_id: CorrelationId,
    /// What the event carried.
    pub details: Value,
    /// The hash of the record before this one.
    pub previous_hash: [u8; 32],
    /// The hash of this record.
    pub hash: [u8; 32],
}

/// Microseconds since 1970: as fine as the database keeps time, so that a
/// record hashes the same before and after it is stored.
fn microseconds(moment: Timestamp) -> i128 {
    moment.unix_timestamp_nanos().div_euclid(1_000)
}

fn to_the_microsecond(moment: Timestamp) -> Timestamp {
    Timestamp::from_unix_timestamp_nanos(microseconds(moment) * 1_000).unwrap_or(moment)
}

/// Writes a value as JSON with the keys of every object in alphabetical
/// order, whatever order they were given in.
fn write_canonical(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Object(fields) => {
            let mut names: Vec<&String> = fields.keys().collect();
            names.sort();
            out.push(b'{');
            for (index, name) in names.into_iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                out.extend_from_slice(Value::String(name.clone()).to_string().as_bytes());
                out.push(b':');
                write_canonical(&fields[name], out);
            }
            out.push(b'}');
        }
        Value::Array(items) => {
            out.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(b',');
                }
                write_canonical(item, out);
            }
            out.push(b']');
        }
        scalar => out.extend_from_slice(scalar.to_string().as_bytes()),
    }
}

fn actor_text(actor: Actor) -> String {
    match actor {
        Actor::User(user) => format!("user:{user}"),
        Actor::Client(client) => format!("client:{client}"),
        Actor::System => "system".to_owned(),
        Actor::Anonymous => "anonymous".to_owned(),
    }
}

impl AuditRecord {
    /// Makes the record that follows `head` in a tenant's chain, from an
    /// event.
    #[must_use]
    pub fn next(
        tenant: TenantId,
        head: &ChainHead,
        event: &EventEnvelope,
        recorded_at: Timestamp,
        digest: &dyn Digest,
    ) -> Self {
        let mut record = Self {
            sequence: head.sequence + 1,
            event_id: event.metadata.event_id,
            action: event.event_type.clone(),
            occurred_at: to_the_microsecond(event.metadata.occurred_at),
            recorded_at: to_the_microsecond(recorded_at),
            actor: event.metadata.actor,
            correlation_id: event.metadata.correlation_id,
            details: event.payload.clone(),
            previous_hash: head.hash,
            hash: [0; 32],
        };
        record.hash = record.computed_hash(tenant, digest);
        record
    }

    /// The hash the record's contents give, whatever hash it carries.
    ///
    /// Every field is preceded by its length, so that no two different
    /// records can produce the same bytes.
    #[must_use]
    pub fn computed_hash(&self, tenant: TenantId, digest: &dyn Digest) -> [u8; 32] {
        let mut details = Vec::new();
        write_canonical(&self.details, &mut details);
        let (tenant, event, correlation) = (
            tenant.as_uuid(),
            self.event_id.as_uuid(),
            self.correlation_id.as_uuid(),
        );
        let (sequence, occurred, actor) = (
            self.sequence.to_be_bytes(),
            microseconds(self.occurred_at).to_be_bytes(),
            actor_text(self.actor),
        );
        let fields: [&[u8]; 10] = [
            DOMAIN,
            tenant.as_bytes(),
            &sequence,
            event.as_bytes(),
            self.action.as_bytes(),
            &occurred,
            actor.as_bytes(),
            correlation.as_bytes(),
            &details,
            &self.previous_hash,
        ];
        let mut input = Vec::new();
        for field in fields {
            input.extend_from_slice(&(field.len() as u64).to_be_bytes());
            input.extend_from_slice(field);
        }
        digest.sha256(&input)
    }

    /// The head of the chain once this record is its last.
    #[must_use]
    pub const fn as_head(&self) -> ChainHead {
        ChainHead {
            sequence: self.sequence,
            hash: self.hash,
        }
    }
}

/// How a chain is broken at a record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainBreak {
    /// The record's sequence is not the one after the record before it: a
    /// record was removed, inserted or repeated.
    SequenceOutOfOrder,
    /// The record's previous hash is not the hash of the record before it.
    PreviousHashMismatch,
    /// The record's contents do not give its hash: it was changed.
    ContentsChanged,
    /// The chain head does not agree with the last record.
    HeadMismatch,
}

impl ChainBreak {
    /// What the break means, for an operator.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::SequenceOutOfOrder => {
                "its sequence is not the next one: a record was removed, inserted or repeated"
            }
            Self::PreviousHashMismatch => {
                "its previous hash is not the hash of the record before it"
            }
            Self::ContentsChanged => "its contents do not match its hash: it was changed",
            Self::HeadMismatch => "the chain head does not agree with the last record",
        }
    }
}

/// The result of checking a tenant's chain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verification {
    /// How many records were checked and found in order.
    pub records: u64,
    /// The sequence of the first record that does not fit, and how. For a
    /// head that does not agree, the sequence is the head's.
    pub broken: Option<(u64, ChainBreak)>,
}

impl Verification {
    /// Whether the whole chain is in order.
    #[must_use]
    pub const fn is_intact(&self) -> bool {
        self.broken.is_none()
    }
}

/// Checks a chain record by record, in order.
pub struct Verifier<'a> {
    tenant: TenantId,
    digest: &'a dyn Digest,
    last: ChainHead,
    broken: Option<(u64, ChainBreak)>,
}

impl std::fmt::Debug for Verifier<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier")
            .field("checked", &self.last.sequence)
            .field("broken", &self.broken)
            .finish_non_exhaustive()
    }
}

impl<'a> Verifier<'a> {
    /// Starts at the beginning of a tenant's chain.
    #[must_use]
    pub fn new(tenant: TenantId, digest: &'a dyn Digest) -> Self {
        Self {
            tenant,
            digest,
            last: ChainHead::EMPTY,
            broken: None,
        }
    }

    /// Checks the next record. After the first break nothing more is
    /// checked: what follows a break cannot be trusted either way.
    pub fn check(&mut self, record: &AuditRecord) {
        if self.broken.is_some() {
            return;
        }
        let problem = if record.sequence != self.last.sequence + 1 {
            Some(ChainBreak::SequenceOutOfOrder)
        } else if record.previous_hash != self.last.hash {
            Some(ChainBreak::PreviousHashMismatch)
        } else if record.computed_hash(self.tenant, self.digest) != record.hash {
            Some(ChainBreak::ContentsChanged)
        } else {
            None
        };
        match problem {
            Some(problem) => self.broken = Some((record.sequence, problem)),
            None => self.last = record.as_head(),
        }
    }

    /// The sequence of the last record found in order.
    #[must_use]
    pub const fn checked(&self) -> u64 {
        self.last.sequence
    }

    /// Whether a break was found.
    #[must_use]
    pub const fn is_broken(&self) -> bool {
        self.broken.is_some()
    }

    /// Ends the check, comparing the stored head with the last record.
    #[must_use]
    pub fn finish(self, head: &ChainHead) -> Verification {
        let broken = self
            .broken
            .or_else(|| (*head != self.last).then_some((head.sequence, ChainBreak::HeadMismatch)));
        Verification {
            records: self.last.sequence,
            broken,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_kernel::random::testing::FakeDigest;
    use hodor_kernel::{EventMetadata, UserId};
    use proptest::prelude::*;
    use serde_json::json;
    use time::Duration;

    fn event(action: &str, payload: Value) -> EventEnvelope {
        EventEnvelope {
            metadata: EventMetadata {
                event_id: EventId::generate(),
                tenant_id: TenantId::generate(),
                occurred_at: Timestamp::UNIX_EPOCH + Duration::nanoseconds(1_234_567_891),
                actor: Actor::User(UserId::generate()),
                correlation_id: CorrelationId::generate(),
            },
            event_type: action.to_owned(),
            payload,
        }
    }

    fn chain(tenant: TenantId, length: u64) -> Vec<AuditRecord> {
        let mut head = ChainHead::EMPTY;
        (0..length)
            .map(|index| {
                let record = AuditRecord::next(
                    tenant,
                    &head,
                    &event("test.happened", json!({ "index": index })),
                    Timestamp::UNIX_EPOCH,
                    &FakeDigest,
                );
                head = record.as_head();
                record
            })
            .collect()
    }

    fn verify(tenant: TenantId, records: &[AuditRecord], head: &ChainHead) -> Verification {
        let mut verifier = Verifier::new(tenant, &FakeDigest);
        for record in records {
            verifier.check(record);
        }
        verifier.finish(head)
    }

    #[test]
    fn the_first_record_follows_zeros_and_each_record_follows_the_one_before() {
        let tenant = TenantId::generate();
        let records = chain(tenant, 3);
        assert_eq!(records[0].sequence, 1);
        assert_eq!(records[0].previous_hash, [0; 32]);
        assert_eq!(records[1].previous_hash, records[0].hash);
        assert_eq!(records[2].previous_hash, records[1].hash);
        assert_eq!(records[2].sequence, 3);
        let verification = verify(tenant, &records, &records[2].as_head());
        assert_eq!(
            verification,
            Verification {
                records: 3,
                broken: None
            }
        );
        assert!(verification.is_intact());
    }

    #[test]
    fn an_empty_chain_is_intact() {
        let verification = verify(TenantId::generate(), &[], &ChainHead::EMPTY);
        assert_eq!(verification.records, 0);
        assert!(verification.is_intact());
    }

    #[test]
    fn a_record_is_kept_to_the_microsecond_and_hashes_the_same_after_storage() {
        let tenant = TenantId::generate();
        let record = AuditRecord::next(
            tenant,
            &ChainHead::EMPTY,
            &event("test.happened", json!({})),
            Timestamp::UNIX_EPOCH,
            &FakeDigest,
        );
        assert_eq!(
            record.occurred_at,
            Timestamp::UNIX_EPOCH + Duration::microseconds(1_234_567)
        );
        assert_eq!(record.computed_hash(tenant, &FakeDigest), record.hash);
    }

    #[test]
    fn the_order_of_keys_in_the_details_does_not_change_the_hash() {
        let tenant = TenantId::generate();
        let mut record = chain(tenant, 1).remove(0);
        record.details =
            serde_json::from_str(r#"{"b":{"y":1,"x":[2,{"q":1,"p":2}]},"a":"é\n"}"#).expect("json");
        let one = record.computed_hash(tenant, &FakeDigest);
        record.details =
            serde_json::from_str(r#"{"a":"é\n","b":{"x":[2,{"p":2,"q":1}],"y":1}}"#).expect("json");
        assert_eq!(record.computed_hash(tenant, &FakeDigest), one);
        // The order of items in a list does matter.
        record.details =
            serde_json::from_str(r#"{"a":"é\n","b":{"x":[{"p":2,"q":1},2],"y":1}}"#).expect("json");
        assert_ne!(record.computed_hash(tenant, &FakeDigest), one);
    }

    #[test]
    fn every_covered_field_changes_the_hash_and_the_recording_time_does_not() {
        let tenant = TenantId::generate();
        let record = chain(tenant, 1).remove(0);
        let original = record.hash;
        let hash_of = |change: &dyn Fn(&mut AuditRecord)| {
            let mut changed = record.clone();
            change(&mut changed);
            changed.computed_hash(tenant, &FakeDigest)
        };

        assert_ne!(hash_of(&|r| r.sequence += 1), original);
        assert_ne!(hash_of(&|r| r.event_id = EventId::generate()), original);
        assert_ne!(hash_of(&|r| r.action.push('x')), original);
        assert_ne!(
            hash_of(&|r| r.occurred_at += Duration::microseconds(1)),
            original
        );
        assert_ne!(hash_of(&|r| r.actor = Actor::System), original);
        assert_ne!(hash_of(&|r| r.actor = Actor::Anonymous), original);
        assert_ne!(
            hash_of(&|r| r.actor = Actor::Client(hodor_kernel::ClientActorId::generate())),
            original
        );
        assert_ne!(
            hash_of(&|r| r.correlation_id = CorrelationId::generate()),
            original
        );
        assert_ne!(hash_of(&|r| r.details = json!({ "index": 1 })), original);
        assert_ne!(hash_of(&|r| r.previous_hash[31] ^= 1), original);
        assert_ne!(
            record.computed_hash(TenantId::generate(), &FakeDigest),
            original,
            "a record does not fit another tenant's chain"
        );
        assert_eq!(hash_of(&|r| r.recorded_at += Duration::hours(1)), original);
    }

    #[test]
    fn fields_cannot_be_shifted_into_each_other() {
        // Without lengths, moving a character from the end of one field
        // to the start of the next would give the same bytes.
        let tenant = TenantId::generate();
        let mut one = chain(tenant, 1).remove(0);
        let mut other = one.clone();
        one.action = "a.b".to_owned();
        one.details = json!("c");
        other.action = "a.b\"".to_owned();
        other.details = json!("");
        assert_ne!(
            one.computed_hash(tenant, &FakeDigest),
            other.computed_hash(tenant, &FakeDigest)
        );
    }

    #[test]
    fn each_kind_of_break_is_told_apart() {
        let tenant = TenantId::generate();
        let records = chain(tenant, 4);
        let head = records[3].as_head();

        let mut changed = records.clone();
        changed[1].details = json!({ "index": 99 });
        assert_eq!(
            verify(tenant, &changed, &head),
            Verification {
                records: 1,
                broken: Some((2, ChainBreak::ContentsChanged))
            }
        );

        let mut removed = records.clone();
        removed.remove(1);
        assert_eq!(
            verify(tenant, &removed, &head).broken,
            Some((3, ChainBreak::SequenceOutOfOrder))
        );

        let mut repeated = records.clone();
        repeated.insert(1, records[0].clone());
        assert_eq!(
            verify(tenant, &repeated, &head).broken,
            Some((1, ChainBreak::SequenceOutOfOrder))
        );

        // A record replaced by one that is valid on its own but follows
        // something else.
        let mut replaced = records.clone();
        let mut stranger = records[1].clone();
        stranger.previous_hash = [7; 32];
        stranger.hash = stranger.computed_hash(tenant, &FakeDigest);
        replaced[1] = stranger;
        assert_eq!(
            verify(tenant, &replaced, &head).broken,
            Some((2, ChainBreak::PreviousHashMismatch))
        );

        // Records removed from the end are noticed only through the head.
        assert_eq!(
            verify(tenant, &records[..2], &head),
            Verification {
                records: 2,
                broken: Some((4, ChainBreak::HeadMismatch))
            }
        );
        assert!(verify(tenant, &records[..2], &records[1].as_head()).is_intact());
    }

    #[test]
    fn every_break_has_a_description() {
        for kind in [
            ChainBreak::SequenceOutOfOrder,
            ChainBreak::PreviousHashMismatch,
            ChainBreak::ContentsChanged,
            ChainBreak::HeadMismatch,
        ] {
            assert!(!kind.description().is_empty());
        }
    }

    proptest! {
        #[test]
        fn changing_any_one_record_of_a_chain_is_noticed_at_that_record(
            length in 1u64..12, position in 0usize..12, field in 0u8..5
        ) {
            let tenant = TenantId::generate();
            let mut records = chain(tenant, length);
            let position = position % records.len();
            let head = records[records.len() - 1].as_head();
            let record = &mut records[position];
            match field {
                0 => record.action.push('!'),
                1 => record.details = json!({ "tampered": true }),
                2 => record.actor = Actor::Anonymous,
                3 => record.occurred_at += Duration::seconds(1),
                _ => record.event_id = EventId::generate(),
            }
            let verification = verify(tenant, &records, &head);
            prop_assert_eq!(
                verification.broken,
                Some((position as u64 + 1, ChainBreak::ContentsChanged))
            );
            prop_assert_eq!(verification.records, position as u64);
        }

        #[test]
        fn removing_any_record_but_the_last_is_noticed(length in 2u64..12, position in 0usize..11) {
            let tenant = TenantId::generate();
            let mut records = chain(tenant, length);
            let position = position % (records.len() - 1);
            let head = records[records.len() - 1].as_head();
            records.remove(position);
            prop_assert!(!verify(tenant, &records, &head).is_intact());
        }
    }
}
