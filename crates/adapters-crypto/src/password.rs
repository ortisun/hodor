//! Password hashing with Argon2id.
//!
//! See `docs/architecture/contexts/credential.md`, "How a password is
//! hashed" and "Protecting the server from the cost of hashing".

use argon2::password_hash::{Error as HashError, PasswordHasher as _, PasswordVerifier as _};
use argon2::{Algorithm, Argon2, Params, Version};
use hodor_credential::api::{PasswordHash, PasswordHasher, PasswordVerification};
use hodor_kernel::{DomainError, ErrorKind, RandomSource, Secret};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::Semaphore;

const SALT_LENGTH: usize = 16;
const OUTPUT_LENGTH: usize = 32;

/// How expensive a hash is. Stored inside every hash, so the values can be
/// raised at any time: older hashes still verify and are renewed the next
/// time their owner signs in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Parameters {
    /// Memory used by one hash, in kibibytes.
    pub memory_kibibytes: u32,
    /// Number of passes over the memory.
    pub passes: u32,
    /// Number of lanes computed in parallel.
    pub lanes: u32,
}

impl Default for Argon2Parameters {
    /// The baseline recommended by OWASP: 19 MiB, 2 passes, 1 lane.
    fn default() -> Self {
        Self {
            memory_kibibytes: 19 * 1024,
            passes: 2,
            lanes: 1,
        }
    }
}

impl Argon2Parameters {
    /// The text every hash made with these parameters starts with.
    fn encoded_prefix(&self) -> String {
        format!(
            "$argon2id$v=19$m={},t={},p={}$",
            self.memory_kibibytes, self.passes, self.lanes
        )
    }
}

/// How much hashing may happen at once.
///
/// The memory the process needs for hashing is `concurrent` times the
/// memory parameter; size the container accordingly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HashingLimits {
    /// Hashes computed at the same time.
    pub concurrent: usize,
    /// Requests allowed to wait for their turn. One more is refused.
    pub queued: usize,
}

impl HashingLimits {
    /// One hash per processor core, and four times as many waiting.
    #[must_use]
    pub fn for_this_machine() -> Self {
        let cores = std::thread::available_parallelism().map_or(1, std::num::NonZero::get);
        Self {
            concurrent: cores,
            queued: cores * 4,
        }
    }
}

/// [`PasswordHasher`] using Argon2id.
///
/// Hashes run on the blocking thread pool, never on the threads that serve
/// requests, and their number is bounded.
pub struct Argon2idHasher {
    parameters: Argon2Parameters,
    engine: Arc<Argon2<'static>>,
    random: Arc<dyn RandomSource>,
    permits: Arc<Semaphore>,
    /// Requests running or waiting.
    admitted: Arc<AtomicUsize>,
    capacity: usize,
    /// A real hash of a throwaway value, verified against when there is
    /// nothing else to check, so that the work done is the same.
    decoy: PasswordHash,
}

impl std::fmt::Debug for Argon2idHasher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Argon2idHasher")
            .field("parameters", &self.parameters)
            .field("capacity", &self.capacity)
            .finish_non_exhaustive()
    }
}

fn internal(detail: impl std::fmt::Display) -> DomainError {
    DomainError::internal(
        "credential.hashing_failed",
        "the operation could not be completed",
    )
    .with_detail(detail.to_string())
}

fn overloaded() -> DomainError {
    DomainError::new(
        ErrorKind::Unavailable,
        "credential.hashing_overloaded",
        "the server is busy; try again in a moment",
    )
}

/// Releases a place in the bounded queue when the request ends, however it
/// ends.
struct Admission(Arc<AtomicUsize>);

impl Drop for Admission {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn hash_with(
    engine: &Argon2<'_>,
    password: &[u8],
    salt: &[u8],
) -> Result<PasswordHash, DomainError> {
    engine
        .hash_password_with_salt(password, salt)
        .map(|hash| PasswordHash::new(hash.to_string()))
        .map_err(internal)
}

impl Argon2idHasher {
    /// Creates a hasher.
    ///
    /// # Errors
    ///
    /// Returns an internal error if the parameters are not valid for
    /// Argon2 or the limits are zero.
    pub fn new(
        parameters: Argon2Parameters,
        limits: HashingLimits,
        random: Arc<dyn RandomSource>,
    ) -> Result<Self, DomainError> {
        if limits.concurrent == 0 {
            return Err(internal("at least one concurrent hash is required"));
        }
        let params = Params::new(
            parameters.memory_kibibytes,
            parameters.passes,
            parameters.lanes,
            Some(OUTPUT_LENGTH),
        )
        .map_err(internal)?;
        let engine = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        // The decoy is a real hash, made with the current parameters, of a
        // random value nobody knows.
        let mut throwaway = [0_u8; 32];
        let mut salt = [0_u8; SALT_LENGTH];
        random.fill(&mut throwaway);
        random.fill(&mut salt);
        let decoy = hash_with(&engine, &throwaway, &salt)?;

        Ok(Self {
            parameters,
            engine: Arc::new(engine),
            random,
            permits: Arc::new(Semaphore::new(limits.concurrent)),
            admitted: Arc::new(AtomicUsize::new(0)),
            capacity: limits.concurrent + limits.queued,
            decoy,
        })
    }

    /// Runs one piece of hashing work within the limits.
    async fn run<T, F>(&self, work: F) -> Result<T, DomainError>
    where
        T: Send + 'static,
        F: FnOnce(&Argon2<'static>) -> Result<T, DomainError> + Send + 'static,
    {
        // Refuse at once when the queue is full, instead of piling up.
        if self.admitted.fetch_add(1, Ordering::SeqCst) >= self.capacity {
            self.admitted.fetch_sub(1, Ordering::SeqCst);
            return Err(overloaded());
        }
        let _admission = Admission(Arc::clone(&self.admitted));
        let permit = Arc::clone(&self.permits)
            .acquire_owned()
            .await
            .map_err(internal)?;
        let engine = Arc::clone(&self.engine);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            work(&engine)
        })
        .await
        .map_err(internal)?
    }

    async fn verify_encoded(
        &self,
        password: &Secret<String>,
        encoded: String,
    ) -> Result<bool, DomainError> {
        // The secret is copied for the blocking thread and wiped there.
        let password = Secret::from(password.expose().clone());
        self.run(move |engine| {
            if !encoded.starts_with("$argon2id$") {
                return Err(internal("stored password hash is not Argon2id"));
            }
            match engine.verify_password(password.expose().as_bytes(), encoded.as_str()) {
                Ok(()) => Ok(true),
                Err(HashError::PasswordInvalid) => Ok(false),
                Err(error) => Err(internal(error)),
            }
        })
        .await
    }
}

#[async_trait::async_trait]
impl PasswordHasher for Argon2idHasher {
    async fn hash(&self, password: &Secret<String>) -> Result<PasswordHash, DomainError> {
        let mut salt = [0_u8; SALT_LENGTH];
        self.random.fill(&mut salt);
        let password = Secret::from(password.expose().clone());
        self.run(move |engine| hash_with(engine, password.expose().as_bytes(), &salt))
            .await
    }

    async fn verify(
        &self,
        password: &Secret<String>,
        hash: &PasswordHash,
    ) -> Result<PasswordVerification, DomainError> {
        let matches = self
            .verify_encoded(password, hash.as_str().to_owned())
            .await?;
        Ok(PasswordVerification {
            matches,
            needs_renewal: !hash.as_str().starts_with(&self.parameters.encoded_prefix()),
        })
    }

    async fn verify_nothing(&self, password: &Secret<String>) -> Result<(), DomainError> {
        self.verify_encoded(password, self.decoy.as_str().to_owned())
            .await
            .map(|_| ())
    }
}
