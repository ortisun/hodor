//! Enrolling a second factor during a sign-in: the authenticator of the
//! last step of the flow, for a person whose tenant requires a second
//! factor and who has none.
//!
//! Specified in `docs/architecture/contexts/authentication.md`, "Enrolling
//! a second factor during a sign-in". It does each thing through the same
//! use cases as the person's own pages, in [`FactorService`].

use crate::application::factors::FactorService;
use crate::domain::authenticator::{
    Authenticator, AuthenticatorTraits, ExternalInput, Factor, StepChallenge, StepInput,
    StepOutcome,
};
use crate::domain::enrollment::{BegunEnrollment, Enrolled, EnrollmentKind};
use crate::domain::transaction::AuthTransaction;
use hodor_credential::api::{RecoveryCodes, RegistrationResponse};
use hodor_identity::api::IdentityService;
use hodor_kernel::{
    Actor, Caller, CorrelationId, DomainError, ErrorKind, Secret, TenantContext, UserId,
};
use serde_json::json;

/// The refusal of beginning or finishing an enrollment for a person who
/// has a second factor by now.
fn not_needed() -> DomainError {
    DomainError::conflict(
        "authentication.enrollment_not_needed",
        "you have a second factor now; start signing in again to use it",
    )
}

/// What the credential context says when an answer simply does not hold:
/// each is a rejection of the step, like a wrong code.
const REFUSALS: [&str; 5] = [
    "credential.totp_code_wrong",
    "credential.totp_enrollment_not_found",
    "credential.webauthn_registration_not_found",
    "credential.webauthn_registration_refused",
    "credential.webauthn_credential_exists",
];

/// Puts a new second factor in use for the candidate, who has none: an
/// authenticator application, a security key or a passkey. Asking for the
/// step's challenge, with the kind among its values, begins the
/// enrollment; submitting the step finishes the one the sign-in began.
#[derive(Clone, Debug)]
pub struct EnrollmentAuthenticator {
    factors: FactorService,
    identity: IdentityService,
}

impl EnrollmentAuthenticator {
    /// The kind flows name it by, the key of its step in the flow the
    /// server runs, and the method recorded for it.
    pub const KIND: &'static str = "enrollment";

    /// Wires the authenticator to the use cases of a person's own factors.
    #[must_use]
    pub const fn new(factors: FactorService, identity: IdentityService) -> Self {
        Self { factors, identity }
    }

    /// The person who may enroll in this sign-in, if anyone: the
    /// candidate, in a sign-in that is not a step-up and proved a factor
    /// itself, who has no second factor.
    async fn eligible(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
    ) -> Result<Option<UserId>, DomainError> {
        let state = transaction.snapshot();
        let (Some(user), None, false) = (
            state.candidate,
            state.raised_session,
            state.satisfied_methods.is_empty(),
        ) else {
            return Ok(None);
        };
        let factors = self.factors.factors(tenant, user).await?;
        Ok((factors.second_factors() == 0).then_some(user))
    }

    async fn may_sign_in(&self, tenant: &TenantContext, user: UserId) -> Result<bool, DomainError> {
        match self.identity.get(tenant, user).await {
            Ok(found) => Ok(found.may_sign_in()),
            Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
            Err(error) => Err(error),
        }
    }
}

/// The events of the enrollment name the person as who did it.
fn person(user: UserId) -> Caller {
    Caller {
        actor: Actor::User(user),
        correlation_id: CorrelationId::generate(),
    }
}

fn shown_once(codes: Option<RecoveryCodes>) -> Vec<Secret<String>> {
    codes.map_or_else(Vec::new, |codes| {
        codes
            .codes()
            .map(|code| Secret::from(code.to_owned()))
            .collect()
    })
}

/// What an authenticator answered to a registration, from the values the
/// interaction interface gave.
fn registration_of(input: &ExternalInput) -> Option<RegistrationResponse> {
    let field = |name: &str| input.field(name).map(|value| value.expose().as_str());
    let transports = field("transports")
        .map(|listed| {
            listed
                .split(',')
                .filter(|transport| !transport.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let discoverable = match field("discoverable") {
        Some("true") => Some(true),
        Some("false") => Some(false),
        _ => None,
    };
    RegistrationResponse::from_base64url(
        field("client_data")?,
        field("attestation_object")?,
        transports,
        discoverable,
        field("name").map(str::to_owned),
    )
}

/// A refusal of the credential context that is an answer that does not
/// hold, as a rejection; anything else is passed on.
fn rejected_or(error: DomainError) -> Result<StepOutcome, DomainError> {
    if REFUSALS.contains(&error.code()) {
        Ok(StepOutcome::Rejected)
    } else {
        Err(error)
    }
}

#[async_trait::async_trait]
impl Authenticator for EnrollmentAuthenticator {
    fn kind(&self) -> &'static str {
        Self::KIND
    }

    fn traits(&self) -> AuthenticatorTraits {
        AuthenticatorTraits {
            identifies: false,
            // The factor is the person's from now on. It was bound by
            // whoever proved the first factor, so it never resists
            // phishing, whatever was enrolled.
            factor: Some(Factor::Possession),
            second_factor: None,
            method: Some(Self::KIND),
        }
    }

    async fn has_means(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
    ) -> Result<bool, DomainError> {
        Ok(!self.factors.enrollable().is_empty()
            && self.eligible(tenant, transaction).await?.is_some())
    }

    async fn challenge(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
        asked: &ExternalInput,
    ) -> Result<Option<StepChallenge>, DomainError> {
        let Some(kind) = asked
            .field("kind")
            .and_then(|kind| EnrollmentKind::parse(kind.expose()))
        else {
            return Err(DomainError::invalid(
                "authentication.enrollment_kind_unknown",
                "say what to set up: authenticator_application, security_key or passkey",
            ));
        };
        let Some(user) = self.eligible(tenant, transaction).await? else {
            return Err(not_needed());
        };
        let (begun, options) = match kind {
            EnrollmentKind::AuthenticatorApplication => {
                let enrollment = self
                    .factors
                    .begin_authenticator_application(tenant, user)
                    .await?;
                let options = json!({
                    "kind": kind.as_str(),
                    "secret": enrollment.secret(),
                    "uri": enrollment.address(),
                });
                (
                    BegunEnrollment::AuthenticatorApplication(enrollment.id()),
                    options,
                )
            }
            EnrollmentKind::SecurityKey | EnrollmentKind::Passkey => {
                let passkey = kind == EnrollmentKind::Passkey;
                let registration = if passkey {
                    self.factors
                        .begin_passkey_registration(tenant, user)
                        .await?
                } else {
                    self.factors
                        .begin_webauthn_registration(tenant, user)
                        .await?
                };
                let options = json!({
                    "kind": kind.as_str(),
                    "public_key": registration.options,
                });
                let begun = if passkey {
                    BegunEnrollment::Passkey(registration.id)
                } else {
                    BegunEnrollment::SecurityKey(registration.id)
                };
                (begun, options)
            }
        };
        Ok(Some(StepChallenge {
            challenge: None,
            enrollment: Some(begun),
            options,
        }))
    }

    async fn perform(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
        input: &StepInput,
    ) -> Result<StepOutcome, DomainError> {
        let Some(user) = self.eligible(tenant, transaction).await? else {
            return Err(not_needed());
        };
        let (StepInput::External(input), Some(begun)) = (input, transaction.begun_enrollment())
        else {
            return Ok(StepOutcome::Rejected);
        };
        if !self.may_sign_in(tenant, user).await? {
            return Ok(StepOutcome::Rejected);
        }
        let caller = person(user);
        let recovery_codes = match begun {
            BegunEnrollment::AuthenticatorApplication(id) => {
                let Some(code) = input.field("code") else {
                    return Ok(StepOutcome::Rejected);
                };
                match self
                    .factors
                    .confirm_begun_authenticator_application(tenant, user, id, code, caller)
                    .await
                {
                    Ok(codes) => codes,
                    Err(error) => return rejected_or(error),
                }
            }
            BegunEnrollment::SecurityKey(id) | BegunEnrollment::Passkey(id) => {
                let Some(response) = registration_of(input) else {
                    return Ok(StepOutcome::Rejected);
                };
                match self
                    .factors
                    .finish_webauthn_registration(tenant, user, id, response, caller)
                    .await
                {
                    Ok(registered) => registered.recovery_codes,
                    Err(error) => return rejected_or(error),
                }
            }
        };
        Ok(StepOutcome::Enrolled(Enrolled {
            kind: begun.kind(),
            recovery_codes: shown_once(recovery_codes),
        }))
    }
}
