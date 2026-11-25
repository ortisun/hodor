//! What the issuer does with each request, with the cluster and Hodor in
//! memory: which requests reach Hodor and which never do, and what is
//! written back for each answer.
//!
//! Specified in `docs/operations/hodor-cert-manager-issuer.md`, "What it
//! signs" and "What it writes back".

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hodor_cert_manager_issuer::request::{
    Addressed, CertificateRequestSpec, CertificateRequestStatus, Condition, IssuerReference,
};
use hodor_cert_manager_issuer::{
    Cluster, ClusterError, Failure, Next, Reconciler, Request, Signed, Signer,
};
use serde_json::Value;
use std::collections::{HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const NOW: &str = "2026-11-25T10:00:00Z";
const PEM: &str = "-----BEGIN CERTIFICATE REQUEST-----\nMIIB\n-----END CERTIFICATE REQUEST-----\n";

/// The cluster in memory: the issuers that exist, and every status
/// written.
#[derive(Default)]
struct Memory {
    issuers: Mutex<HashSet<(String, String)>>,
    written: Mutex<Vec<(String, Value)>>,
}

#[async_trait]
impl Cluster for Memory {
    async fn issuer_exists(
        &self,
        namespace: &str,
        addressed: &Addressed,
    ) -> Result<bool, ClusterError> {
        let key = match addressed {
            Addressed::Issuer(name) => (namespace.to_owned(), name.clone()),
            Addressed::ClusterIssuer(name) => (String::new(), name.clone()),
        };
        Ok(self.issuers.lock().expect("lock").contains(&key))
    }

    async fn write_status(&self, request: &Request, status: Value) -> Result<(), ClusterError> {
        self.written
            .lock()
            .expect("lock")
            .push((request.name.clone(), status));
        Ok(())
    }
}

impl Memory {
    fn with_issuer(namespace: &str, name: &str) -> Arc<Self> {
        let memory = Self::default();
        memory
            .issuers
            .lock()
            .expect("lock")
            .insert((namespace.to_owned(), name.to_owned()));
        Arc::new(memory)
    }

    fn written(&self) -> Vec<Value> {
        self.written
            .lock()
            .expect("lock")
            .iter()
            .map(|(_, status)| status.clone())
            .collect()
    }
}

/// Hodor in memory: answers in turn, and every request it was sent.
#[derive(Default)]
struct Answers {
    answers: Mutex<VecDeque<Result<Signed, Failure>>>,
    sent: Mutex<Vec<(String, Option<u32>)>>,
}

#[async_trait]
impl Signer for Answers {
    async fn sign(&self, request: &str, lifetime_days: Option<u32>) -> Result<Signed, Failure> {
        self.sent
            .lock()
            .expect("lock")
            .push((request.to_owned(), lifetime_days));
        self.answers
            .lock()
            .expect("lock")
            .pop_front()
            .unwrap_or_else(|| Err(Failure::Unavailable("no answer".to_owned())))
    }

    async fn check_access(&self) -> Result<(), Failure> {
        Ok(())
    }
}

impl Answers {
    fn giving(answers: Vec<Result<Signed, Failure>>) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers.into()),
            sent: Mutex::new(Vec::new()),
        })
    }

    fn sent(&self) -> Vec<(String, Option<u32>)> {
        self.sent.lock().expect("lock").clone()
    }
}

fn signed() -> Signed {
    Signed {
        id: "0193f3b1-0000-7000-8000-000000000001".to_owned(),
        serial_number: "41c2".to_owned(),
        certificate: "-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n".to_owned(),
        chain: vec!["-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----\n".to_owned()],
    }
}

fn request(name: &str, conditions: &[(&str, &str)]) -> Request {
    Request {
        namespace: "linkerd".to_owned(),
        name: name.to_owned(),
        uid: format!("uid-{name}"),
        resource_version: Some("7".to_owned()),
        spec: CertificateRequestSpec {
            request: STANDARD.encode(PEM),
            is_ca: true,
            duration: Some("48h0m0s".to_owned()),
            issuer_ref: IssuerReference {
                name: "hodor".to_owned(),
                kind: Some("HodorIssuer".to_owned()),
                group: Some("hodor.ortisun.github.io".to_owned()),
            },
        },
        status: Some(CertificateRequestStatus {
            conditions: conditions
                .iter()
                .map(|(kind, status)| Condition {
                    kind: (*kind).to_owned(),
                    status: (*status).to_owned(),
                    ..Condition::default()
                })
                .collect(),
        }),
    }
}

/// The request as it is once `status` was merged into it.
fn after(mut request: Request, status: &Value) -> Request {
    let conditions: Vec<Condition> =
        serde_json::from_value(status["conditions"].clone()).expect("conditions");
    request.status = Some(CertificateRequestStatus { conditions });
    request
}

fn ready(status: &Value) -> &Value {
    status["conditions"]
        .as_array()
        .expect("conditions")
        .iter()
        .find(|condition| condition["type"] == "Ready")
        .expect("Ready")
}

#[tokio::test]
async fn an_approved_request_for_an_authority_is_signed_and_written_with_its_root_apart() {
    let cluster = Memory::with_issuer("linkerd", "hodor");
    let hodor = Answers::giving(vec![Ok(signed())]);
    let issuer = Reconciler::new(cluster.clone(), hodor.clone());

    let approved = request("linkerd-identity-issuer-1", &[("Approved", "True")]);
    assert_eq!(
        issuer.reconcile(&approved, NOW).await.expect("done"),
        Next::WhenChanged
    );
    assert_eq!(hodor.sent(), vec![(PEM.to_owned(), Some(2))]);
    let written = cluster.written();
    assert_eq!(written.len(), 1);
    let status = &written[0];
    assert_eq!(ready(status)["status"], "True");
    assert_eq!(ready(status)["reason"], "Issued");
    assert!(
        ready(status)["message"]
            .as_str()
            .expect("message")
            .contains("0193f3b1-0000-7000-8000-000000000001")
    );
    assert_eq!(
        status["certificate"],
        STANDARD.encode("-----BEGIN CERTIFICATE-----\nLEAF\n-----END CERTIFICATE-----\n")
    );
    assert_eq!(
        status["ca"],
        STANDARD.encode("-----BEGIN CERTIFICATE-----\nROOT\n-----END CERTIFICATE-----\n")
    );
    // The approval is kept beside it.
    assert_eq!(status["conditions"][0]["type"], "Approved");

    // Finished: looked at again, it is never sent again.
    let finished = after(approved, status);
    assert_eq!(
        issuer.reconcile(&finished, NOW).await.expect("done"),
        Next::WhenChanged
    );
    assert_eq!(hodor.sent().len(), 1);
    assert_eq!(cluster.written().len(), 1);
}

#[tokio::test]
async fn an_unapproved_request_is_never_sent_until_it_is_approved() {
    let cluster = Memory::with_issuer("linkerd", "hodor");
    let hodor = Answers::giving(vec![Ok(signed())]);
    let issuer = Reconciler::new(cluster.clone(), hodor.clone());

    for conditions in [
        &[][..],
        &[("Approved", "False")][..],
        &[("Ready", "False")][..],
    ] {
        let waiting = request("waiting", conditions);
        assert_eq!(
            issuer.reconcile(&waiting, NOW).await.expect("done"),
            Next::WhenChanged
        );
    }
    let mut without_status = request("waiting", &[]);
    without_status.status = None;
    issuer.reconcile(&without_status, NOW).await.expect("done");
    assert!(hodor.sent().is_empty(), "nothing sent");
    assert!(cluster.written().is_empty(), "nothing written");

    issuer
        .reconcile(&request("waiting", &[("Approved", "True")]), NOW)
        .await
        .expect("done");
    assert_eq!(hodor.sent().len(), 1);
}

#[tokio::test]
async fn a_denied_request_is_marked_denied_and_never_sent() {
    let cluster = Memory::with_issuer("linkerd", "hodor");
    let hodor = Answers::giving(vec![Ok(signed())]);
    let issuer = Reconciler::new(cluster.clone(), hodor.clone());

    let denied = request("denied", &[("Denied", "True")]);
    issuer.reconcile(&denied, NOW).await.expect("done");
    let written = cluster.written();
    assert_eq!(written.len(), 1);
    assert_eq!(ready(&written[0])["status"], "False");
    assert_eq!(ready(&written[0])["reason"], "Denied");
    assert_eq!(written[0]["failureTime"], NOW);
    assert!(written[0].get("certificate").is_none());

    issuer
        .reconcile(&after(denied, &written[0]), NOW)
        .await
        .expect("done");
    assert!(hodor.sent().is_empty());
    assert_eq!(cluster.written().len(), 1);
}

#[tokio::test]
async fn a_request_that_is_not_for_an_authority_is_failed_and_never_sent() {
    let cluster = Memory::with_issuer("linkerd", "hodor");
    let hodor = Answers::giving(vec![Ok(signed())]);
    let issuer = Reconciler::new(cluster.clone(), hodor.clone());

    let mut workload = request("a-workload", &[("Approved", "True")]);
    workload.spec.is_ca = false;
    issuer.reconcile(&workload, NOW).await.expect("done");
    let written = cluster.written();
    assert_eq!(ready(&written[0])["reason"], "Failed");
    assert!(
        ready(&written[0])["message"]
            .as_str()
            .expect("message")
            .contains("not for an authority")
    );
    assert_eq!(written[0]["failureTime"], NOW);
    assert!(hodor.sent().is_empty());
}

#[tokio::test]
async fn a_request_for_another_issuer_is_left_alone() {
    let cluster = Memory::with_issuer("linkerd", "hodor");
    let hodor = Answers::giving(vec![Ok(signed())]);
    let issuer = Reconciler::new(cluster.clone(), hodor.clone());

    let mut other = request("other", &[("Approved", "True")]);
    other.spec.issuer_ref.group = Some("cert-manager.io".to_owned());
    other.spec.issuer_ref.kind = Some("ClusterIssuer".to_owned());
    issuer.reconcile(&other, NOW).await.expect("done");
    assert!(hodor.sent().is_empty());
    assert!(cluster.written().is_empty());
}

#[tokio::test]
async fn a_request_whose_issuer_is_missing_waits_and_goes_through_once_it_exists() {
    let cluster = Arc::new(Memory::default());
    let hodor = Answers::giving(vec![Ok(signed())]);
    let issuer =
        Reconciler::new(cluster.clone(), hodor.clone()).with_first_wait(Duration::from_millis(50));

    // In another namespace, and of the other kind, it does not count.
    cluster
        .issuers
        .lock()
        .expect("lock")
        .insert(("istio-system".to_owned(), "hodor".to_owned()));
    let orphan = request("orphan", &[("Approved", "True")]);
    let Next::After(wait) = issuer.reconcile(&orphan, NOW).await.expect("done") else {
        panic!("it waits");
    };
    assert_eq!(wait, Duration::from_millis(50));
    let written = cluster.written();
    assert_eq!(ready(&written[0])["reason"], "Pending");
    assert!(
        ready(&written[0])["message"]
            .as_str()
            .expect("message")
            .contains("does not exist in the namespace linkerd")
    );
    assert!(written[0].get("failureTime").is_none());
    assert!(hodor.sent().is_empty());

    cluster
        .issuers
        .lock()
        .expect("lock")
        .insert(("linkerd".to_owned(), "hodor".to_owned()));
    tokio::time::sleep(Duration::from_millis(60)).await;
    let pending = after(orphan, &written[0]);
    assert_eq!(
        issuer.reconcile(&pending, NOW).await.expect("done"),
        Next::WhenChanged
    );
    assert_eq!(hodor.sent().len(), 1);
    assert_eq!(ready(&cluster.written()[1])["reason"], "Issued");
}

#[tokio::test]
async fn a_refusal_of_hodors_is_named_in_the_condition_and_never_sent_again() {
    let cluster = Memory::with_issuer("linkerd", "hodor");
    let hodor = Answers::giving(vec![Err(Failure::Refused {
        status: 422,
        code: "keys.intermediate_name_outside_trust_domains".to_owned(),
        detail: "identity.linkerd.other.example is outside the authority's trust domains"
            .to_owned(),
    })]);
    let issuer = Reconciler::new(cluster.clone(), hodor.clone());

    let outside = request("outside", &[("Approved", "True")]);
    assert_eq!(
        issuer.reconcile(&outside, NOW).await.expect("done"),
        Next::WhenChanged
    );
    let written = cluster.written();
    assert_eq!(ready(&written[0])["status"], "False");
    assert_eq!(ready(&written[0])["reason"], "Failed");
    assert_eq!(
        ready(&written[0])["message"],
        "Hodor refused the request: keys.intermediate_name_outside_trust_domains: \
         identity.linkerd.other.example is outside the authority's trust domains"
    );
    assert_eq!(written[0]["failureTime"], NOW);

    issuer
        .reconcile(&after(outside, &written[0]), NOW)
        .await
        .expect("done");
    assert_eq!(hodor.sent().len(), 1, "never sent again");
}

#[tokio::test]
async fn with_hodor_unreachable_the_request_waits_and_is_signed_once_hodor_is_back() {
    let cluster = Memory::with_issuer("", "hodor");
    let hodor = Answers::giving(vec![
        Err(Failure::Unavailable(
            "the token endpoint could not be reached: connection refused".to_owned(),
        )),
        Err(Failure::Unavailable(
            "the token endpoint could not be reached: connection refused".to_owned(),
        )),
        Ok(signed()),
    ]);
    let issuer =
        Reconciler::new(cluster.clone(), hodor.clone()).with_first_wait(Duration::from_millis(40));

    let mut renewal = request("renewal", &[("Approved", "True")]);
    renewal.spec.issuer_ref.kind = Some("HodorClusterIssuer".to_owned());
    renewal.spec.duration = None;
    let Next::After(first) = issuer.reconcile(&renewal, NOW).await.expect("done") else {
        panic!("it waits");
    };
    assert_eq!(first, Duration::from_millis(40));
    let written = cluster.written();
    assert_eq!(ready(&written[0])["reason"], "Pending");
    assert_eq!(
        ready(&written[0])["message"],
        "Hodor could not sign: the token endpoint could not be reached: connection refused"
    );
    let pending = after(renewal, &written[0]);

    // Its own change of status brings it back at once: it is not sent
    // before the wait is over.
    assert!(matches!(
        issuer.reconcile(&pending, NOW).await.expect("done"),
        Next::After(_)
    ));
    assert_eq!(hodor.sent().len(), 1);

    // Still unreachable: the wait doubles, and the same reason is not
    // written again.
    tokio::time::sleep(Duration::from_millis(50)).await;
    let Next::After(second) = issuer.reconcile(&pending, NOW).await.expect("done") else {
        panic!("it waits");
    };
    assert_eq!(second, Duration::from_millis(80));
    assert_eq!(hodor.sent().len(), 2);
    assert_eq!(cluster.written().len(), 1);

    // Back: signed, for the authority's bound since it names no duration.
    tokio::time::sleep(Duration::from_millis(90)).await;
    assert_eq!(
        issuer.reconcile(&pending, NOW).await.expect("done"),
        Next::WhenChanged
    );
    assert_eq!(hodor.sent()[2], (PEM.to_owned(), None));
    assert_eq!(ready(&cluster.written()[1])["reason"], "Issued");
}
