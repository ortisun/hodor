//! The built-in templates and how they become a message.
//!
//! A template is a subject and a body in plain text with named
//! placeholders, written as `{name}`.

use hodor_kernel::DomainError;
use std::collections::BTreeMap;

/// Which message is being sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Template {
    /// A person must prove control of an email address.
    EmailVerification,
    /// Someone tried to register with an address that already has an account.
    AlreadyRegistered,
    /// A person asked to choose a new password.
    PasswordRecovery,
    /// A password was changed.
    PasswordChanged,
    /// A person is invited to join an organization.
    OrganizationInvitation,
}

impl Template {
    /// Every template.
    pub const ALL: [Self; 5] = [
        Self::EmailVerification,
        Self::AlreadyRegistered,
        Self::PasswordRecovery,
        Self::PasswordChanged,
        Self::OrganizationInvitation,
    ];

    /// The name the template is stored and reported under.
    #[must_use]
    pub const fn key(self) -> &'static str {
        match self {
            Self::EmailVerification => "email_verification",
            Self::AlreadyRegistered => "already_registered",
            Self::PasswordRecovery => "password_recovery",
            Self::PasswordChanged => "password_changed",
            Self::OrganizationInvitation => "organization_invitation",
        }
    }

    /// Reads a stored template name.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if there is no such template.
    pub fn from_key(key: &str) -> Result<Self, DomainError> {
        Self::ALL
            .into_iter()
            .find(|template| template.key() == key)
            .ok_or_else(|| {
                DomainError::invalid(
                    "notification.unknown_template",
                    "there is no such message template",
                )
            })
    }

    /// The variables the template needs. All must be given, and no others.
    #[must_use]
    pub const fn variables(self) -> &'static [&'static str] {
        match self {
            Self::EmailVerification | Self::PasswordRecovery => {
                &["link", "tenant_name", "expires_at"]
            }
            Self::AlreadyRegistered | Self::PasswordChanged => &["tenant_name"],
            Self::OrganizationInvitation => {
                &["link", "tenant_name", "organization_name", "expires_at"]
            }
        }
    }

    const fn text(self, language: Language) -> (&'static str, &'static str) {
        match (self, language) {
            (Self::EmailVerification, Language::English) => (
                "Confirm your email address for {tenant_name}",
                "Hello,\n\n\
                 Someone, hopefully you, used this address to create an account at {tenant_name}.\n\n\
                 To confirm that the address is yours, open this link:\n\n\
                 {link}\n\n\
                 The link works once and stops working on {expires_at}.\n\n\
                 If it was not you, ignore this message and nothing will happen.\n",
            ),
            (Self::EmailVerification, Language::Portuguese) => (
                "Confirme seu endereço de email em {tenant_name}",
                "Olá,\n\n\
                 Alguém, esperamos que você, usou este endereço para criar uma conta em {tenant_name}.\n\n\
                 Para confirmar que o endereço é seu, abra este link:\n\n\
                 {link}\n\n\
                 O link funciona uma única vez e deixa de funcionar em {expires_at}.\n\n\
                 Se não foi você, ignore esta mensagem e nada acontecerá.\n",
            ),
            (Self::AlreadyRegistered, Language::English) => (
                "You already have an account at {tenant_name}",
                "Hello,\n\n\
                 Someone, hopefully you, tried to create an account at {tenant_name} with this address, \
                 but the address already has one.\n\n\
                 If it was you, sign in as usual. If you do not remember your password, \
                 ask for a new one on the sign-in page.\n\n\
                 If it was not you, ignore this message. Your account was not changed.\n",
            ),
            (Self::AlreadyRegistered, Language::Portuguese) => (
                "Você já tem uma conta em {tenant_name}",
                "Olá,\n\n\
                 Alguém, esperamos que você, tentou criar uma conta em {tenant_name} com este endereço, \
                 mas o endereço já tem uma.\n\n\
                 Se foi você, entre como de costume. Se não lembra da senha, \
                 peça uma nova na página de entrada.\n\n\
                 Se não foi você, ignore esta mensagem. Sua conta não foi alterada.\n",
            ),
            (Self::PasswordRecovery, Language::English) => (
                "Choose a new password for {tenant_name}",
                "Hello,\n\n\
                 Someone, hopefully you, asked to choose a new password for your account at {tenant_name}.\n\n\
                 To choose it, open this link:\n\n\
                 {link}\n\n\
                 The link works once and stops working on {expires_at}.\n\n\
                 If it was not you, ignore this message. Your password stays as it is.\n",
            ),
            (Self::PasswordRecovery, Language::Portuguese) => (
                "Escolha uma nova senha para {tenant_name}",
                "Olá,\n\n\
                 Alguém, esperamos que você, pediu para escolher uma nova senha para a sua conta em {tenant_name}.\n\n\
                 Para escolher, abra este link:\n\n\
                 {link}\n\n\
                 O link funciona uma única vez e deixa de funcionar em {expires_at}.\n\n\
                 Se não foi você, ignore esta mensagem. Sua senha continua a mesma.\n",
            ),
            (Self::PasswordChanged, Language::English) => (
                "Your password for {tenant_name} was changed",
                "Hello,\n\n\
                 The password of your account at {tenant_name} was just changed.\n\n\
                 If it was you, there is nothing to do.\n\n\
                 If it was not you, choose a new password now on the sign-in page \
                 and tell the people who run {tenant_name}.\n",
            ),
            (Self::PasswordChanged, Language::Portuguese) => (
                "Sua senha em {tenant_name} foi alterada",
                "Olá,\n\n\
                 A senha da sua conta em {tenant_name} acaba de ser alterada.\n\n\
                 Se foi você, não há nada a fazer.\n\n\
                 Se não foi você, escolha uma nova senha agora na página de entrada \
                 e avise as pessoas responsáveis por {tenant_name}.\n",
            ),
            (Self::OrganizationInvitation, Language::English) => (
                "You are invited to join {organization_name} at {tenant_name}",
                "Hello,\n\n\
                 You are invited to join {organization_name} at {tenant_name}.\n\n\
                 To accept, open this link:\n\n\
                 {link}\n\n\
                 If you have no account yet, you will choose a password there. \
                 The link works once and stops working on {expires_at}.\n\n\
                 If you do not know why you were invited, ignore this message and nothing will happen.\n",
            ),
            (Self::OrganizationInvitation, Language::Portuguese) => (
                "Você foi convidado para {organization_name} em {tenant_name}",
                "Olá,\n\n\
                 Você foi convidado para fazer parte de {organization_name} em {tenant_name}.\n\n\
                 Para aceitar, abra este link:\n\n\
                 {link}\n\n\
                 Se ainda não tiver uma conta, você escolherá uma senha lá. \
                 O link funciona uma única vez e deixa de funcionar em {expires_at}.\n\n\
                 Se não souber por que foi convidado, ignore esta mensagem e nada acontecerá.\n",
            ),
        }
    }

    /// Writes the message in the language that best fits `locale`.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if a variable the template needs is missing.
    pub fn render(
        self,
        recipient: &str,
        locale: &str,
        variables: &BTreeMap<String, String>,
    ) -> Result<Email, DomainError> {
        let (subject, body) = self.text(Language::for_locale(locale));
        Ok(Email {
            recipient: recipient.to_owned(),
            subject: fill(subject, variables)?,
            body: fill(body, variables)?,
        })
    }
}

/// The languages templates are written in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Language {
    English,
    Portuguese,
}

impl Language {
    /// The requested locale if there is a template for it, otherwise the
    /// same language without the region, otherwise English.
    fn for_locale(locale: &str) -> Self {
        let language = locale.split(['-', '_']).next().unwrap_or_default();
        if language.eq_ignore_ascii_case("pt") {
            Self::Portuguese
        } else {
            Self::English
        }
    }
}

/// Replaces each `{name}` once, reading the text a single time, so that a
/// value which itself contains `{other}` is inserted as it is.
fn fill(text: &str, variables: &BTreeMap<String, String>) -> Result<String, DomainError> {
    let mut filled = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(open) = rest.find('{') {
        filled.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let Some(close) = after.find('}') else {
            filled.push_str(&rest[open..]);
            rest = "";
            break;
        };
        let name = &after[..close];
        let value = variables.get(name).ok_or_else(|| {
            DomainError::invalid(
                "notification.missing_variable",
                "the message is missing a value it needs",
            )
            .with_detail(format!("variable `{name}` was not given"))
        })?;
        filled.push_str(value);
        rest = &after[close + 1..];
    }
    filled.push_str(rest);
    Ok(filled)
}

/// A message ready to hand to a mail server.
#[derive(Clone, PartialEq, Eq)]
pub struct Email {
    /// The address to send to.
    pub recipient: String,
    /// The subject line.
    pub subject: String,
    /// The body, in plain text.
    pub body: String,
}

impl std::fmt::Debug for Email {
    /// The body is left out: it may contain a link that is as good as a
    /// token.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Email")
            .field("subject", &self.subject)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn variables(template: Template) -> BTreeMap<String, String> {
        template
            .variables()
            .iter()
            .map(|name| ((*name).to_owned(), format!("<{name}>")))
            .collect()
    }

    #[test]
    fn every_template_renders_in_every_language_with_exactly_its_variables() {
        for template in Template::ALL {
            for locale in ["en", "pt-BR"] {
                let email = template
                    .render("person@example.com", locale, &variables(template))
                    .expect("renders");
                let text = format!("{}\n{}", email.subject, email.body);
                assert!(!text.contains('{') && !text.contains('}'), "{text}");
                for name in template.variables() {
                    assert!(
                        text.contains(&format!("<{name}>")),
                        "{} in {locale} does not use `{name}`",
                        template.key()
                    );
                }
            }
        }
    }

    #[test]
    fn subjects_never_contain_the_link() {
        for template in Template::ALL {
            for locale in ["en", "pt-BR"] {
                let email = template
                    .render("person@example.com", locale, &variables(template))
                    .expect("renders");
                assert!(!email.subject.contains("<link>"));
                assert!(!email.subject.contains('\n'));
            }
        }
    }

    #[test]
    fn the_language_falls_back_to_the_same_language_and_then_to_english() {
        let template = Template::PasswordChanged;
        let subject = |locale: &str| {
            template
                .render("person@example.com", locale, &variables(template))
                .expect("renders")
                .subject
        };
        assert_eq!(subject("pt-BR"), subject("pt-PT"));
        assert_eq!(subject("pt"), subject("PT_br"));
        assert_ne!(subject("pt-BR"), subject("en"));
        assert_eq!(subject("fr-FR"), subject("en"));
        assert_eq!(subject(""), subject("en-GB"));
    }

    #[test]
    fn a_missing_variable_is_an_error() {
        let error = Template::EmailVerification
            .render("person@example.com", "en", &BTreeMap::new())
            .expect_err("missing");
        assert_eq!(error.code(), "notification.missing_variable");
    }

    #[test]
    fn a_value_that_looks_like_a_placeholder_is_inserted_as_it_is() {
        let mut given = variables(Template::EmailVerification);
        given.insert("tenant_name".to_owned(), "{link}".to_owned());
        let email = Template::EmailVerification
            .render("person@example.com", "en", &given)
            .expect("renders");
        assert_eq!(email.subject, "Confirm your email address for {link}");
    }

    #[test]
    fn stored_names_round_trip() {
        for template in Template::ALL {
            assert_eq!(Template::from_key(template.key()).ok(), Some(template));
        }
        assert!(Template::from_key("nope").is_err());
    }

    #[test]
    fn debug_output_leaves_the_body_out() {
        let email = Template::EmailVerification
            .render(
                "person@example.com",
                "en",
                &variables(Template::EmailVerification),
            )
            .expect("renders");
        let shown = format!("{email:?}");
        assert!(!shown.contains("<link>"));
        assert!(!shown.contains("person@example.com"));
    }
}
