//! Authenticating a client by the identity a trusted proxy forwarded:
//! `tls_client_auth`, `spiffe_x509` and `linkerd_identity`.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "An identity
//! forwarded by a proxy", and Decision 0056.

use crate::application::token::TokenService;
use crate::domain::client::{AuthenticationMethod, Client};
use crate::domain::forwarded::{
    CertificateNames, ForwardedIdentity, WorkloadIdentity, names_match,
};
use hodor_kernel::{DomainError, TenantContext, Timestamp};
use hodor_keys::api::{SvidKind, TrustSource};

impl TokenService {
    /// Checks the identity a trusted proxy forwarded with the request of
    /// `client`, a client of a forwarded identity, against the tenant's
    /// trust domain of the client's identity.
    ///
    /// # Errors
    ///
    /// The outer error is a failure of storage; the inner one the reason
    /// the client is refused, for Hodor's log.
    pub(crate) async fn check_forwarded(
        &self,
        tenant: &TenantContext,
        client: &Client,
        forwarded: Option<&ForwardedIdentity>,
        now: Timestamp,
    ) -> Result<Result<(), &'static str>, DomainError> {
        let settings = &client.snapshot().settings;
        let method = settings.authentication_method;
        let (Some(trust_domains), Some(certificates)) = (&self.trust_domains, &self.certificates)
        else {
            return Ok(Err("this server checks no forwarded identity"));
        };
        let Some(forwarded) = forwarded else {
            return Ok(Err("no identity was forwarded by a trusted proxy"));
        };
        let Some(identity) = settings.workload_identity() else {
            return Ok(Err("the client is bound to no identity"));
        };
        let takes_certificate = matches!(
            method,
            AuthenticationMethod::TlsClientAuth | AuthenticationMethod::SpiffeX509
        );
        let fits = match forwarded {
            ForwardedIdentity::Certificate { .. } | ForwardedIdentity::Names { .. } => {
                takes_certificate
            }
            ForwardedIdentity::Linkerd(_) => method == AuthenticationMethod::LinkerdIdentity,
        };
        if !fits {
            return Ok(Err(
                "the forwarded identity is not of the kind the method takes",
            ));
        }
        let Some(trust_domain) = trust_domains
            .find_by_name(tenant, identity.trust_domain())
            .await?
        else {
            return Ok(Err(
                "the trust domain of the client's identity is not trusted",
            ));
        };
        let checked_by_mesh = trust_domain.source() == TrustSource::Mesh;
        // The keys of the intermediates the tenant's authority signed and
        // an administrator withdrew: read at every request, so that a
        // withdrawal holds from the next one.
        let withdrawn = match forwarded {
            ForwardedIdentity::Certificate { .. } if trust_domain.bundle().is_some() => {
                trust_domains.withdrawn_keys(tenant).await?
            }
            _ => Vec::new(),
        };
        let verdict = match forwarded {
            ForwardedIdentity::Linkerd(asserted) => match identity {
                WorkloadIdentity::Linkerd(bound) if bound.as_str() == asserted => {
                    if checked_by_mesh {
                        Ok(())
                    } else {
                        Err(
                            "a Linkerd identity is believed only for a trust domain checked by \
                             the mesh",
                        )
                    }
                }
                _ => Err("the forwarded Linkerd identity is not the client's"),
            },
            ForwardedIdentity::Names {
                uris, dns_names, ..
            } => {
                let names = CertificateNames {
                    uris: uris.clone(),
                    dns_names: dns_names.clone(),
                };
                let believed = if checked_by_mesh {
                    Ok(())
                } else {
                    Err(
                        "names without a certificate are believed only for a trust domain \
                         checked by the mesh",
                    )
                };
                names_match(method, &identity, &names).and(believed)
            }
            ForwardedIdentity::Certificate { certificate, chain } => {
                match certificates.names(certificate) {
                    None => Err("the forwarded certificate does not read"),
                    Some(names) => names_match(method, &identity, &names).and_then(|()| {
                        match trust_domain.bundle() {
                            // The mesh checked it, and there is no bundle
                            // to check it against.
                            None if checked_by_mesh => Ok(()),
                            None => Err("the trust domain has no bundle"),
                            Some(bundle) => {
                                let authorities: Vec<&str> = bundle
                                    .keys()
                                    .iter()
                                    .filter(|key| key.kind == SvidKind::X509)
                                    .map(|key| key.jwk.as_str())
                                    .collect();
                                if certificates.chains_to(
                                    certificate,
                                    chain,
                                    &authorities,
                                    &withdrawn,
                                    now,
                                ) {
                                    Ok(())
                                } else {
                                    Err("the certificate does not chain to the trust domain's \
                                         bundle")
                                }
                            }
                        }
                    }),
                }
            }
        };
        Ok(verdict)
    }
}
