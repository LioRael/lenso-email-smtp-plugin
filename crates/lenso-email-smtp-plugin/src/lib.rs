//! TLS-only SMTP implementation of `lenso.email-dispatch@1`.

mod operator;
mod schema;
mod storage;
mod transport;

use std::{cell::RefCell, collections::BTreeSet, fmt, rc::Rc, time::Duration};

use lenso::prelude::*;
use lenso_capability_email_dispatch as email;
use lenso_capability_secrets as secrets;
use lenso_kernel::RuntimeFailure;
use lenso_postgres_kit::OwnedPostgres;
use lettre::Address;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::Zeroizing;

pub use operator::{EmailSmtpOperator, OperatorError};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TlsMode {
    ImplicitTls,
    StarttlsRequired,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SmtpConfig {
    pub(crate) schema: String,
    pub(crate) database_url_secret: String,
    pub(crate) provider: String,
    pub(crate) smtp_host: String,
    pub(crate) smtp_port: u16,
    pub(crate) tls_mode: TlsMode,
    pub(crate) username_secret_ref: String,
    pub(crate) password_secret_ref: String,
    pub(crate) from_address: String,
    pub(crate) from_name: Option<String>,
    pub(crate) message_id_domain: String,
    pub(crate) command_timeout_ms: u64,
    pub(crate) effect_lease_ms: u64,
    pub(crate) max_message_bytes: usize,
    pub(crate) allowed_callers: Vec<String>,
}

impl fmt::Debug for SmtpConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SmtpConfig")
            .field("schema", &self.schema)
            .field("provider", &self.provider)
            .field("smtp_host", &self.smtp_host)
            .field("smtp_port", &self.smtp_port)
            .field("tls_mode", &self.tls_mode)
            .field("from_address", &"<redacted>")
            .field("message_id_domain", &self.message_id_domain)
            .field("command_timeout_ms", &self.command_timeout_ms)
            .field("effect_lease_ms", &self.effect_lease_ms)
            .field("max_message_bytes", &self.max_message_bytes)
            .field("allowed_callers", &self.allowed_callers)
            .finish_non_exhaustive()
    }
}

impl SmtpConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        schema::schema_plan(self.schema.clone()).map_err(|_| ConfigError::Schema)?;
        if !valid_secret_ref(&self.database_url_secret)
            || !valid_secret_ref(&self.username_secret_ref)
            || !valid_secret_ref(&self.password_secret_ref)
            || self.username_secret_ref == self.password_secret_ref
        {
            return Err(ConfigError::Secrets);
        }
        if !valid_id(&self.provider, 160)
            || !valid_hostname(&self.smtp_host)
            || !valid_hostname(&self.message_id_domain)
            || self.smtp_port == 0
        {
            return Err(ConfigError::Endpoint);
        }
        if !(3..=320).contains(&self.from_address.chars().count())
            || self.from_address.parse::<Address>().is_err()
            || self
                .from_name
                .as_ref()
                .is_some_and(|name| name.chars().count() > 160 || name.contains(['\r', '\n']))
        {
            return Err(ConfigError::Sender);
        }
        if !(1_000..=120_000).contains(&self.command_timeout_ms)
            || !(2_000..=300_000).contains(&self.effect_lease_ms)
            || self.effect_lease_ms < self.command_timeout_ms.saturating_add(1_500)
            || !(1_024..=1_048_576).contains(&self.max_message_bytes)
        {
            return Err(ConfigError::Limits);
        }
        if self.allowed_callers.is_empty()
            || self.allowed_callers.len() > 64
            || self
                .allowed_callers
                .iter()
                .any(|caller| !valid_id(caller, 200))
            || self.allowed_callers.iter().collect::<BTreeSet<_>>().len()
                != self.allowed_callers.len()
        {
            return Err(ConfigError::Callers);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
enum ConfigError {
    #[error("invalid PostgreSQL schema")]
    Schema,
    #[error("invalid or aliased secret reference")]
    Secrets,
    #[error("invalid SMTP endpoint or provider identifier")]
    Endpoint,
    #[error("invalid sender mailbox")]
    Sender,
    #[error("invalid timeout, lease, or message-size limit")]
    Limits,
    #[error("caller allowlist must contain unique Instance keys")]
    Callers,
}

fn valid_secret_ref(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && !value.chars().any(char::is_whitespace)
}

fn valid_id(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

fn valid_hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.starts_with('.')
        && !value.ends_with('.')
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn validate_config(config: &SmtpConfig) -> Result<(), RuntimeFailure> {
    config
        .validate()
        .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: format!("SMTP Plugin configuration is invalid: {error}"),
        })
}

#[derive(Clone, Debug)]
struct Prepared {
    postgres: OwnedPostgres,
}

#[lenso::plugin(lifecycle,configuration_schema="configuration.schema.json",validate=validate_config)]
#[derive(Clone)]
struct EmailSmtpPlugin {
    #[config]
    config: SmtpConfig,
    secrets: Port<secrets::SecretsClient>,
    prepared: Rc<RefCell<Option<Prepared>>>,
}

impl fmt::Debug for EmailSmtpPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailSmtpPlugin")
            .field("provider", &self.config.provider)
            .field("smtp_host", &self.config.smtp_host)
            .field("prepared", &self.prepared.borrow().is_some())
            .finish_non_exhaustive()
    }
}

#[lenso::provides(email::EmailDispatch)]
impl EmailSmtpPlugin {}

impl EmailSmtpPlugin {
    fn prepared(&self) -> Result<Prepared, RuntimeFailure> {
        self.prepared
            .borrow()
            .clone()
            .ok_or_else(|| RuntimeFailure::PluginFailure {
                detail: "SMTP Plugin is not active".to_owned(),
            })
    }

    fn allowed(&self, context: &Ctx) -> bool {
        context.caller_instance().is_some_and(|caller| {
            self.config
                .allowed_callers
                .iter()
                .any(|allowed| allowed == caller)
        })
    }

    async fn resolve_secret(
        &self,
        context: &Ctx,
        reference: &str,
    ) -> Result<Zeroizing<String>, RuntimeFailure> {
        self.secrets
            .resolve_with_context(
                context.clone(),
                secrets::ResolveRequest {
                    reference: reference.to_owned(),
                },
            )
            .await
            .map(|response| Zeroizing::new(response.value))
            .map_err(|error| match error {
                secrets::SecretsInvocationError::Runtime(error) => error,
                secrets::SecretsInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                    detail: "required SMTP credential was rejected".to_owned(),
                },
            })
    }

    async fn wait_for_inflight(
        &self,
        postgres: &OwnedPostgres,
        identity: &storage::DispatchIdentity,
        expired_response: &email::DispatchResponse,
    ) -> Result<email::DispatchResponse, RuntimeFailure> {
        loop {
            match storage::effect_status(postgres, &identity.idempotency_key_hash)
                .await
                .map_err(storage_runtime)?
            {
                storage::EffectStatus::Final(response) => return Ok(response),
                storage::EffectStatus::InFlight { remaining_ms } => {
                    if remaining_ms <= 0 {
                        return match storage::begin_dispatch(
                            postgres,
                            identity,
                            i64::try_from(self.config.effect_lease_ms).unwrap_or(i64::MAX),
                            expired_response,
                        )
                        .await
                        .map_err(storage_runtime)?
                        {
                            storage::BeginDispatch::Replay(response) => Ok(response),
                            storage::BeginDispatch::InFlight { .. } => continue,
                            storage::BeginDispatch::Send { .. } => {
                                Err(RuntimeFailure::PluginFailure {
                                    detail: "SMTP dispatch fence unexpectedly reopened".to_owned(),
                                })
                            }
                        };
                    }
                    tokio::time::sleep(Duration::from_millis(
                        u64::try_from(remaining_ms).unwrap_or(50).min(50),
                    ))
                    .await;
                }
            }
        }
    }
}

impl EmailSmtpPlugin {
    async fn dispatch(
        &self,
        context: Ctx,
        request: email::DispatchRequest,
    ) -> PluginResult<email::DispatchResponse, email::DispatchError> {
        if !self.allowed(&context) {
            return Err(PluginError::domain(email::DispatchError::InvalidDispatch));
        }
        let prepared_message =
            transport::prepare_dispatch(&self.config, &request).map_err(|error| {
                PluginError::domain(match error {
                    transport::PrepareError::Invalid => email::DispatchError::InvalidDispatch,
                    transport::PrepareError::Unsupported => {
                        email::DispatchError::UnsupportedMessage
                    }
                })
            })?;
        let prepared = self.prepared().map_err(PluginError::runtime)?;
        let identity = storage::DispatchIdentity {
            idempotency_key_hash: prepared_message.idempotency_key_hash.clone(),
            delivery_id_hash: prepared_message.delivery_id_hash.clone(),
            attempt_id_hash: prepared_message.attempt_id_hash.clone(),
            request_fingerprint: prepared_message.request_fingerprint.clone(),
            content_digest: request.message.content_digest.clone(),
        };
        let expired_response =
            transport::unknown_response(&self.config.provider, "smtp_effect_lease_expired");
        let begin = storage::begin_dispatch(
            &prepared.postgres,
            &identity,
            i64::try_from(self.config.effect_lease_ms).unwrap_or(i64::MAX),
            &expired_response,
        )
        .await;
        let fence = match begin {
            Ok(storage::BeginDispatch::Replay(response)) => return Ok(response),
            Ok(storage::BeginDispatch::InFlight { .. }) => {
                return self
                    .wait_for_inflight(&prepared.postgres, &identity, &expired_response)
                    .await
                    .map_err(PluginError::runtime);
            }
            Ok(storage::BeginDispatch::Send { fence }) => fence,
            Err(storage::StorageError::Conflict) => {
                return Err(PluginError::domain(email::DispatchError::InvalidDispatch));
            }
            Err(error) => return Err(PluginError::runtime(storage_runtime(error))),
        };

        let credentials = match (
            self.resolve_secret(&context, &self.config.username_secret_ref)
                .await,
            self.resolve_secret(&context, &self.config.password_secret_ref)
                .await,
        ) {
            (Ok(username), Ok(password)) => Some((username, password)),
            _ => None,
        };
        let response = if let Some((username, password)) = credentials {
            transport::send_smtp(&self.config, &username, &password, prepared_message).await
        } else {
            transport::temporary_response(
                &self.config.provider,
                "smtp_credentials_unavailable",
                60_000,
            )
        };
        storage::finalize_dispatch(
            &prepared.postgres,
            &identity.idempotency_key_hash,
            fence,
            &response,
        )
        .await
        .map_err(storage_runtime)
        .map_err(PluginError::runtime)
    }
}

fn storage_runtime(error: storage::StorageError) -> RuntimeFailure {
    match error {
        storage::StorageError::Conflict => RuntimeFailure::PluginFailure {
            detail: "SMTP dispatch identity conflict escaped domain mapping".to_owned(),
        },
        storage::StorageError::Runtime(error) => error,
    }
}

impl Lifecycle for EmailSmtpPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        let database_url = resolve_activation_secret(
            &self.secrets,
            context.dependencies(),
            context.cancellation(),
            &self.config.database_url_secret,
        )
        .await?;
        let postgres = OwnedPostgres::prepare(
            &database_url,
            schema::schema_plan(self.config.schema.clone()).map_err(|error| {
                RuntimeFailure::InvalidResolvedPlan {
                    detail: error.to_string(),
                }
            })?,
        )
        .await
        .map_err(|error| RuntimeFailure::PluginFailure {
            detail: error.to_string(),
        })?;
        self.prepared.borrow_mut().replace(Prepared { postgres });
        Ok(())
    }

    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        let prepared = self.prepared.borrow_mut().take();
        if let Some(prepared) = prepared {
            prepared.postgres.pool().close().await;
        }
        Ok(())
    }
}

async fn resolve_activation_secret(
    secrets: &secrets::SecretsClient,
    dependencies: &lenso_kernel::PluginDependencies,
    cancellation: lenso_kernel::CancellationToken,
    reference: &str,
) -> Result<Zeroizing<String>, RuntimeFailure> {
    let context = dependencies.invocation_context_after(Duration::from_secs(10), cancellation)?;
    secrets
        .resolve_with_context(
            context,
            secrets::ResolveRequest {
                reference: reference.to_owned(),
            },
        )
        .await
        .map(|response| Zeroizing::new(response.value))
        .map_err(|error| match error {
            secrets::SecretsInvocationError::Runtime(error) => error,
            secrets::SecretsInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                detail: "required SMTP database secret was rejected".to_owned(),
            },
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> SmtpConfig {
        SmtpConfig {
            schema: "smtp".into(),
            database_url_secret: "secret://postgres/smtp".into(),
            provider: "smtp-primary".into(),
            smtp_host: "smtp.example.com".into(),
            smtp_port: 465,
            tls_mode: TlsMode::ImplicitTls,
            username_secret_ref: "secret://smtp/username".into(),
            password_secret_ref: "secret://smtp/password".into(),
            from_address: "hello@example.com".into(),
            from_name: Some("Example".into()),
            message_id_domain: "mail.example.com".into(),
            command_timeout_ms: 10_000,
            effect_lease_ms: 12_000,
            max_message_bytes: 900_000,
            allowed_callers: vec!["notification".into()],
        }
    }

    #[test]
    fn validates_tls_only_configuration_and_lease_boundary() {
        config().validate().unwrap();
        let mut invalid = config();
        invalid.effect_lease_ms = invalid.command_timeout_ms;
        assert_eq!(invalid.validate(), Err(ConfigError::Limits));
    }

    #[test]
    fn debug_redacts_all_secret_references_and_sender_address() {
        let debug = format!("{:?}", config());
        assert!(!debug.contains("secret://"));
        assert!(!debug.contains("hello@example.com"));
        assert!(debug.contains("smtp.example.com"));
    }

    #[test]
    fn rejects_plaintext_or_url_shaped_endpoints_by_construction() {
        let mut invalid = config();
        invalid.smtp_host = "smtp://smtp.example.com".into();
        assert_eq!(invalid.validate(), Err(ConfigError::Endpoint));
    }
}

#[cfg(all(test, feature = "postgres-acceptance"))]
mod postgres_tests;
