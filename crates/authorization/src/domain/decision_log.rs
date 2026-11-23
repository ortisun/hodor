//! The record of decisions: what a tenant keeps of each decision, and how
//! much of what the engine was given.
//!
//! See `docs/architecture/contexts/authorization.md`, "The record of
//! decisions".

use crate::domain::decision::AuthorizationDecision;
use crate::domain::request::{Attributes, AuthorizationRequest, SubjectKind};
use crate::domain::role::Effect;
use hodor_kernel::{DomainError, Timestamp};
use serde_json::{Map, Value};

/// The fewest days a tenant may keep its records.
pub const MIN_RETENTION_DAYS: u16 = 1;
/// The most days a tenant may keep its records; partitions older than this
/// are dropped whatever the tenant's setting.
pub const MAX_RETENTION_DAYS: u16 = 400;
/// The days a tenant keeps its records unless it says otherwise.
pub const DEFAULT_RETENTION_DAYS: u16 = 30;
/// The most masks a tenant may set.
pub const MAX_MASKS: usize = 32;
/// The longest a mask may be, in characters.
pub const MAX_MASK_LENGTH: usize = 200;

fn invalid(detail: impl Into<String>) -> DomainError {
    DomainError::invalid(
        "authorization.decision_log_invalid",
        "the settings of the record of decisions are not acceptable",
    )
    .with_detail(detail.into())
}

/// Which decisions are recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecisionLogMode {
    /// Every decision.
    Full,
    /// Every refusal and indeterminate decision, and this share of the
    /// allows, in percent.
    Sampled {
        /// From 1 to 99.
        allow_percent: u8,
    },
    /// Refusals and indeterminate decisions only.
    DenyOnly,
    /// Nothing.
    Off,
}

impl DecisionLogMode {
    /// Reads a mode by its name and, for `sampled`, its share of allows.
    ///
    /// # Errors
    ///
    /// `authorization.decision_log_invalid` for an unknown name, a share
    /// outside 1 to 99, a share without `sampled` or `sampled` without one.
    pub fn parse(name: &str, allow_percent: Option<u8>) -> Result<Self, DomainError> {
        match (name, allow_percent) {
            ("full", None) => Ok(Self::Full),
            ("deny_only", None) => Ok(Self::DenyOnly),
            ("off", None) => Ok(Self::Off),
            ("sampled", Some(percent)) if (1..=99).contains(&percent) => Ok(Self::Sampled {
                allow_percent: percent,
            }),
            ("sampled", Some(_)) => Err(invalid("the share of allows is from 1 to 99 percent")),
            ("sampled", None) => Err(invalid("sampled needs a share of allows")),
            ("full" | "deny_only" | "off", Some(_)) => {
                Err(invalid("a share of allows is given with sampled only"))
            }
            _ => Err(invalid("the mode is full, sampled, deny_only or off")),
        }
    }

    /// The mode's name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Sampled { .. } => "sampled",
            Self::DenyOnly => "deny_only",
            Self::Off => "off",
        }
    }

    /// The share of allows kept, for `sampled`.
    #[must_use]
    pub const fn allow_percent(self) -> Option<u8> {
        match self {
            Self::Sampled { allow_percent } => Some(allow_percent),
            _ => None,
        }
    }

    /// Whether a decision of this effect is kept. `draw` is a number from 0
    /// to 99, drawn at random for each decision; only `sampled` looks at it.
    #[must_use]
    pub fn keeps(self, effect: Effect, draw: u8) -> bool {
        let refused = effect != Effect::Allow;
        match self {
            Self::Full => true,
            Self::Off => false,
            Self::DenyOnly => refused,
            Self::Sampled { allow_percent } => refused || draw < allow_percent,
        }
    }
}

/// The part of the input a mask starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MaskRoot {
    Subject,
    Asserted,
    Resource,
    Context,
}

/// A path into the input whose value is erased before a record is stored,
/// such as `subject.attributes.email` or `resource.attributes.*`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MaskPath(String);

impl MaskPath {
    /// Reads a mask.
    ///
    /// # Errors
    ///
    /// `authorization.decision_log_invalid` unless the path starts with
    /// `subject.attributes.`, `asserted.`, `resource.attributes.` or
    /// `context.attributes.`, names at least one member after it, has no
    /// empty segment, uses `*` only alone as the last segment, and is at
    /// most 200 characters.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        if value.is_empty() || value.chars().count() > MAX_MASK_LENGTH {
            return Err(invalid("a mask is from 1 to 200 characters"));
        }
        let path = Self(value.to_owned());
        let segments = path.members();
        if segments.is_none() {
            return Err(invalid(format!(
                "{value}: a mask starts with subject.attributes, asserted, resource.attributes or context.attributes and names a member after it"
            )));
        }
        let members = segments.unwrap_or_default();
        for (position, segment) in members.iter().enumerate() {
            let last = position + 1 == members.len();
            if segment.is_empty()
                || (segment.contains('*') && (*segment != "*" || !last))
                || segment.chars().any(char::is_control)
            {
                return Err(invalid(format!(
                    "{value}: every segment has a name, and * stands alone as the last one"
                )));
            }
        }
        Ok(path)
    }

    /// The mask as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn root(&self) -> Option<(MaskRoot, &str)> {
        [
            (MaskRoot::Subject, "subject.attributes."),
            (MaskRoot::Asserted, "asserted."),
            (MaskRoot::Resource, "resource.attributes."),
            (MaskRoot::Context, "context.attributes."),
        ]
        .into_iter()
        .find_map(|(root, prefix)| self.0.strip_prefix(prefix).map(|rest| (root, rest)))
    }

    /// The members after the root, or `None` when the root is not one a
    /// mask may start from.
    fn members(&self) -> Option<Vec<&str>> {
        let (_, rest) = self.root()?;
        Some(rest.split('.').collect())
    }
}

/// What a tenant keeps of its decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecisionLogSettings {
    mode: DecisionLogMode,
    masks: Vec<MaskPath>,
    retention_days: u16,
}

impl Default for DecisionLogSettings {
    fn default() -> Self {
        Self {
            mode: DecisionLogMode::Full,
            masks: Vec::new(),
            retention_days: DEFAULT_RETENTION_DAYS,
        }
    }
}

impl DecisionLogSettings {
    /// Checks a set of settings. Repeated masks are kept once.
    ///
    /// # Errors
    ///
    /// `authorization.decision_log_invalid` for more than 32 masks or a
    /// retention outside 1 to 400 days.
    pub fn new(
        mode: DecisionLogMode,
        mut masks: Vec<MaskPath>,
        retention_days: u16,
    ) -> Result<Self, DomainError> {
        masks.sort();
        masks.dedup();
        if masks.len() > MAX_MASKS {
            return Err(invalid("at most 32 masks"));
        }
        if !(MIN_RETENTION_DAYS..=MAX_RETENTION_DAYS).contains(&retention_days) {
            return Err(invalid("the retention is from 1 to 400 days"));
        }
        Ok(Self {
            mode,
            masks,
            retention_days,
        })
    }

    /// Which decisions are recorded.
    #[must_use]
    pub const fn mode(&self) -> DecisionLogMode {
        self.mode
    }

    /// The masks, in order.
    #[must_use]
    pub fn masks(&self) -> &[MaskPath] {
        &self.masks
    }

    /// How many days records are kept.
    #[must_use]
    pub const fn retention_days(&self) -> u16 {
        self.retention_days
    }

    /// The input of a decision as it is stored: what the engine was given,
    /// with every mask applied, and the masks that erased something.
    #[must_use]
    pub fn reduced_input(
        &self,
        request: &AuthorizationRequest,
        subject_attributes: &Attributes,
        asserted_trusted: bool,
    ) -> (Value, Vec<String>) {
        let mut subject = to_object(subject_attributes);
        let mut asserted = if asserted_trusted {
            to_object(&request.asserted)
        } else {
            Map::new()
        };
        let mut resource = to_object(request.resource.attributes());
        let mut context = to_object(&request.context.attributes);
        let mut applied = Vec::new();
        for mask in &self.masks {
            let Some((root, rest)) = mask.root() else {
                continue;
            };
            let target = match root {
                MaskRoot::Subject => &mut subject,
                MaskRoot::Asserted => &mut asserted,
                MaskRoot::Resource => &mut resource,
                MaskRoot::Context => &mut context,
            };
            let segments: Vec<&str> = rest.split('.').collect();
            if erase(target, &segments) {
                applied.push(mask.as_str().to_owned());
            }
        }
        let mut input = Map::new();
        input.insert(
            "subject".into(),
            Value::Object(Map::from_iter([(
                "attributes".into(),
                Value::Object(subject),
            )])),
        );
        if asserted_trusted {
            input.insert("asserted".into(), Value::Object(asserted));
        }
        input.insert(
            "resource".into(),
            Value::Object(Map::from_iter([(
                "attributes".into(),
                Value::Object(resource),
            )])),
        );
        let mut context_object = Map::from_iter([("attributes".into(), Value::Object(context))]);
        if let Some(application) = &request.context.application {
            context_object.insert(
                "application".into(),
                Value::String(application.as_str().to_owned()),
            );
        }
        input.insert("context".into(), Value::Object(context_object));
        (Value::Object(input), applied)
    }
}

fn to_object(attributes: &Attributes) -> Map<String, Value> {
    attributes
        .iter()
        .map(|(name, value)| (name.to_owned(), value.clone()))
        .collect()
}

/// Removes what `segments` names from `object`. Returns whether anything
/// was removed.
fn erase(object: &mut Map<String, Value>, segments: &[&str]) -> bool {
    match segments {
        [] => false,
        ["*"] => {
            let had = !object.is_empty();
            object.clear();
            had
        }
        [last] => object.remove(*last).is_some(),
        [first, rest @ ..] => match object.get_mut(*first) {
            Some(Value::Object(inner)) => erase(inner, rest),
            _ => false,
        },
    }
}

/// One recorded decision.
#[derive(Debug, Clone, PartialEq)]
pub struct DecisionRecord {
    /// The answer's identifier.
    pub decision_id: crate::domain::decision::DecisionId,
    /// The resource server asked about.
    pub namespace: String,
    /// The subject's kind.
    pub subject_kind: SubjectKind,
    /// The subject's identifier.
    pub subject_id: String,
    /// The action.
    pub action: String,
    /// The resource's type.
    pub resource_type: String,
    /// The resource's identifier, when the request named one.
    pub resource_id: Option<String>,
    /// The answer.
    pub effect: Effect,
    /// Its stable reason.
    pub reason: String,
    /// The engine that decided, when one did.
    pub engine: Option<String>,
    /// The revision or version it decided with.
    pub policy_version: Option<String>,
    /// When it was decided.
    pub decided_at: Timestamp,
    /// How long it took.
    pub duration_microseconds: u64,
    /// The input, reduced by the tenant's masks.
    pub input: Value,
    /// The masks that erased something.
    pub masked: Vec<String>,
}

impl DecisionRecord {
    /// The record of `decision`, made for `request` with what Hodor knew
    /// of its subject, reduced by `settings`.
    #[must_use]
    pub fn of(
        settings: &DecisionLogSettings,
        request: &AuthorizationRequest,
        subject_attributes: &Attributes,
        decision: &AuthorizationDecision,
    ) -> Self {
        let (input, masked) = settings.reduced_input(
            request,
            subject_attributes,
            decision.metadata.asserted_trusted,
        );
        Self {
            decision_id: decision.decision_id,
            namespace: request.namespace.as_str().to_owned(),
            subject_kind: request.subject.kind(),
            subject_id: request.subject.id().to_owned(),
            action: request.action.as_str().to_owned(),
            resource_type: request.resource.kind().to_owned(),
            resource_id: request.resource.id().map(str::to_owned),
            effect: decision.effect,
            reason: decision.reason.as_str().to_owned(),
            engine: decision
                .engine
                .as_ref()
                .map(|engine| engine.as_str().to_owned()),
            policy_version: decision
                .policy_version
                .as_ref()
                .map(|version| version.as_str().to_owned()),
            decided_at: decision.evaluated_at,
            duration_microseconds: decision.metadata.duration_microseconds,
            input,
            masked,
        }
    }
}

/// Which records to read.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DecisionFilter {
    /// Decided at or after this time.
    pub from: Option<Timestamp>,
    /// Decided before this time.
    pub to: Option<Timestamp>,
    /// With this effect.
    pub effect: Option<Effect>,
    /// About this resource server.
    pub namespace: Option<String>,
    /// About this subject: its kind and identifier.
    pub subject: Option<(SubjectKind, String)>,
}

impl DecisionFilter {
    /// Whether a record passes the filter.
    #[must_use]
    pub fn matches(&self, record: &DecisionRecord) -> bool {
        self.from.is_none_or(|from| record.decided_at >= from)
            && self.to.is_none_or(|to| record.decided_at < to)
            && self.effect.is_none_or(|effect| record.effect == effect)
            && self
                .namespace
                .as_ref()
                .is_none_or(|namespace| &record.namespace == namespace)
            && self
                .subject
                .as_ref()
                .is_none_or(|(kind, id)| record.subject_kind == *kind && &record.subject_id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::request::{Action, EvaluationContext, Namespace, Resource, Subject};
    use serde_json::json;

    fn attributes(value: Value) -> Attributes {
        let Value::Object(map) = value else {
            panic!("an object");
        };
        Attributes::new(map).expect("attributes")
    }

    fn request() -> AuthorizationRequest {
        AuthorizationRequest {
            namespace: Namespace::parse("https://api.example.com").expect("namespace"),
            subject: Subject::new(SubjectKind::User, "0193f1c4-0000-7000-8000-000000000001")
                .expect("subject"),
            asserted: attributes(json!({ "department": "sales" })),
            resource: Resource::new(
                "document",
                Some("42"),
                attributes(json!({ "owner": "ana@example.com", "secret": { "pin": "1234", "label": "x" } })),
            )
            .expect("resource"),
            action: Action::parse("read").expect("action"),
            context: EvaluationContext {
                attributes: attributes(json!({ "ip": "203.0.113.7" })),
                ..EvaluationContext::default()
            },
        }
    }

    #[test]
    fn modes_are_read_with_their_share() {
        assert_eq!(
            DecisionLogMode::parse("full", None),
            Ok(DecisionLogMode::Full)
        );
        assert_eq!(
            DecisionLogMode::parse("sampled", Some(10)),
            Ok(DecisionLogMode::Sampled { allow_percent: 10 })
        );
        for (name, share) in [
            ("sampled", None),
            ("sampled", Some(0)),
            ("sampled", Some(100)),
            ("full", Some(5)),
            ("everything", None),
        ] {
            assert_eq!(
                DecisionLogMode::parse(name, share).map_err(|e| e.code().to_owned()),
                Err("authorization.decision_log_invalid".to_owned()),
                "{name} {share:?}"
            );
        }
    }

    #[test]
    fn each_mode_keeps_what_it_says() {
        use Effect::{Allow, Deny, Indeterminate};
        let sampled = DecisionLogMode::Sampled { allow_percent: 25 };
        assert!(DecisionLogMode::Full.keeps(Allow, 99));
        assert!(!DecisionLogMode::Off.keeps(Deny, 0));
        assert!(!DecisionLogMode::DenyOnly.keeps(Allow, 0));
        assert!(DecisionLogMode::DenyOnly.keeps(Deny, 99));
        assert!(DecisionLogMode::DenyOnly.keeps(Indeterminate, 99));
        assert!(sampled.keeps(Deny, 99));
        assert!(sampled.keeps(Allow, 24));
        assert!(!sampled.keeps(Allow, 25));
        let kept = (0..100).filter(|draw| sampled.keeps(Allow, *draw)).count();
        assert_eq!(kept, 25);
    }

    #[test]
    fn a_mask_must_name_a_member_under_an_allowed_root() {
        for good in [
            "subject.attributes.email",
            "asserted.department",
            "resource.attributes.*",
            "resource.attributes.secret.pin",
            "context.attributes.ip",
        ] {
            assert!(MaskPath::parse(good).is_ok(), "{good}");
        }
        let long = format!("subject.attributes.{}", "a".repeat(200));
        for bad in [
            "",
            "subject.id",
            "subject.attributes",
            "subject.attributes.",
            "resource.*",
            "input.anything",
            "resource.attributes.*.pin",
            "resource.attributes.se*",
            "context.attributes..ip",
            long.as_str(),
        ] {
            assert_eq!(
                MaskPath::parse(bad).map_err(|e| e.code().to_owned()),
                Err("authorization.decision_log_invalid".to_owned()),
                "{bad}"
            );
        }
    }

    #[test]
    fn settings_have_bounds() {
        let masks = |n: usize| {
            (0..n)
                .map(|i| MaskPath::parse(&format!("context.attributes.a{i}")).expect("mask"))
                .collect::<Vec<_>>()
        };
        assert!(DecisionLogSettings::new(DecisionLogMode::Full, masks(32), 1).is_ok());
        assert!(DecisionLogSettings::new(DecisionLogMode::Full, masks(33), 30).is_err());
        assert!(DecisionLogSettings::new(DecisionLogMode::Full, Vec::new(), 0).is_err());
        assert!(DecisionLogSettings::new(DecisionLogMode::Full, Vec::new(), 401).is_err());
        let twice = vec![
            MaskPath::parse("context.attributes.ip").expect("mask"),
            MaskPath::parse("context.attributes.ip").expect("mask"),
        ];
        let settings = DecisionLogSettings::new(DecisionLogMode::Full, twice, 400).expect("ok");
        assert_eq!(settings.masks().len(), 1);
        assert_eq!(DecisionLogSettings::default().retention_days(), 30);
    }

    #[test]
    fn masks_erase_what_they_name_and_nothing_else() {
        let settings = DecisionLogSettings::new(
            DecisionLogMode::Full,
            vec![
                MaskPath::parse("subject.attributes.email").expect("mask"),
                MaskPath::parse("resource.attributes.secret.pin").expect("mask"),
                MaskPath::parse("context.attributes.*").expect("mask"),
                MaskPath::parse("asserted.missing").expect("mask"),
            ],
            30,
        )
        .expect("settings");
        let subject = attributes(json!({ "email": "ana@example.com", "status": "active" }));
        let (input, masked) = settings.reduced_input(&request(), &subject, true);
        assert_eq!(
            input,
            json!({
                "subject": { "attributes": { "status": "active" } },
                "asserted": { "department": "sales" },
                "resource": { "attributes": { "owner": "ana@example.com", "secret": { "label": "x" } } },
                "context": { "attributes": {} }
            })
        );
        assert_eq!(
            masked,
            [
                "context.attributes.*",
                "resource.attributes.secret.pin",
                "subject.attributes.email"
            ]
        );
    }

    #[test]
    fn untrusted_asserted_attributes_are_not_recorded() {
        let (input, _) =
            DecisionLogSettings::default().reduced_input(&request(), &Attributes::none(), false);
        assert!(input.get("asserted").is_none());
        assert!(!input.to_string().contains("sales"));
    }

    #[test]
    fn a_filter_selects_by_each_field() {
        let decided_at = Timestamp::from_unix_timestamp(1_800_000_000).expect("time");
        let record = DecisionRecord {
            decision_id: crate::domain::decision::DecisionId::generate(),
            namespace: "https://api.example.com".into(),
            subject_kind: SubjectKind::User,
            subject_id: "ana".into(),
            action: "read".into(),
            resource_type: "document".into(),
            resource_id: None,
            effect: Effect::Deny,
            reason: "no_matching_role".into(),
            engine: Some("native".into()),
            policy_version: None,
            decided_at,
            duration_microseconds: 5,
            input: json!({}),
            masked: Vec::new(),
        };
        assert!(DecisionFilter::default().matches(&record));
        let filter = |f: DecisionFilter| f.matches(&record);
        assert!(filter(DecisionFilter {
            from: Some(decided_at),
            ..Default::default()
        }));
        assert!(!filter(DecisionFilter {
            to: Some(decided_at),
            ..Default::default()
        }));
        assert!(!filter(DecisionFilter {
            effect: Some(Effect::Allow),
            ..Default::default()
        }));
        assert!(!filter(DecisionFilter {
            namespace: Some("other".into()),
            ..Default::default()
        }));
        assert!(filter(DecisionFilter {
            subject: Some((SubjectKind::User, "ana".into())),
            ..Default::default()
        }));
        assert!(!filter(DecisionFilter {
            subject: Some((SubjectKind::Client, "ana".into())),
            ..Default::default()
        }));
    }
}
