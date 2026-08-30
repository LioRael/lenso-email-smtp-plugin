use std::time::Duration;

use chrono::{SecondsFormat, Utc};
use lenso_capability_email_dispatch as email;
use lettre::{
    Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, MultiPart, SinglePart, header::ContentType},
    transport::smtp::{
        Error as SmtpError, authentication::Credentials, response::Response as SmtpResponse,
    },
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{SmtpConfig, TlsMode};

const DIGEST_PREFIX: &str = "sha256:";

#[derive(Debug)]
pub(crate) struct PreparedDispatch {
    pub message: Message,
    pub message_id: String,
    pub idempotency_key_hash: String,
    pub delivery_id_hash: String,
    pub attempt_id_hash: String,
    pub request_fingerprint: String,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PrepareError {
    Invalid,
    Unsupported,
}

fn digest_parts<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(u64::try_from(part.len()).unwrap_or(u64::MAX).to_be_bytes());
        hasher.update(part);
    }
    format!("{DIGEST_PREFIX}{}", hex::encode(hasher.finalize()))
}

pub(crate) fn digest_text(value: &str) -> String {
    digest_parts([value.as_bytes()])
}

fn bounded(value: &str, minimum: usize, maximum: usize) -> bool {
    let length = value.chars().count();
    (minimum..=maximum).contains(&length)
}

fn valid_locale(value: &str) -> bool {
    bounded(value, 2, 32)
}

fn content_digest(message: &email::DispatchRequestMessage) -> String {
    digest_parts([
        message.subject.as_bytes(),
        message.text.as_bytes(),
        message.html.as_bytes(),
    ])
}

fn request_fingerprint(request: &email::DispatchRequest) -> String {
    digest_parts([
        request.delivery_id.as_bytes(),
        request.attempt_id.as_bytes(),
        request.run_id.as_bytes(),
        request.idempotency_key.as_bytes(),
        request.recipient.address.as_bytes(),
        request.message.template_id.as_bytes(),
        request.message.template_version.as_bytes(),
        request.message.locale.as_bytes(),
        request.message.subject.as_bytes(),
        request.message.text.as_bytes(),
        request.message.html.as_bytes(),
        request.message.content_digest.as_bytes(),
        request.correlation_id.as_bytes(),
    ])
}

fn estimated_encoded_size(request: &email::DispatchRequest) -> Option<usize> {
    let content = request
        .message
        .subject
        .len()
        .checked_add(request.message.text.len())?
        .checked_add(request.message.html.len())?
        .checked_add(request.recipient.address.len())?;
    content.checked_mul(3)?.checked_add(8192)
}

pub(crate) fn prepare_dispatch(
    config: &SmtpConfig,
    request: &email::DispatchRequest,
) -> Result<PreparedDispatch, PrepareError> {
    if !bounded(&request.delivery_id, 1, 160)
        || !bounded(&request.attempt_id, 1, 160)
        || !bounded(&request.run_id, 1, 160)
        || !bounded(&request.idempotency_key, 1, 240)
        || !bounded(&request.correlation_id, 1, 240)
        || !bounded(&request.message.template_id, 1, 160)
        || !bounded(&request.message.template_version, 1, 80)
        || !valid_locale(&request.message.locale)
        || !bounded(&request.recipient.address, 3, 320)
        || request.message.subject.is_empty()
        || request.message.subject.chars().count() > 998
        || request.message.subject.contains(['\r', '\n'])
        || request.message.text.is_empty()
        || request.message.text.chars().count() > 131_072
        || request.message.html.is_empty()
        || request.message.html.chars().count() > 262_144
        || content_digest(&request.message) != request.message.content_digest
    {
        return Err(PrepareError::Invalid);
    }
    if estimated_encoded_size(request).is_none_or(|size| size > config.max_message_bytes) {
        return Err(PrepareError::Unsupported);
    }

    let recipient = request
        .recipient
        .address
        .parse::<Address>()
        .map_err(|_| PrepareError::Invalid)?;
    let sender = config
        .from_address
        .parse::<Address>()
        .map_err(|_| PrepareError::Invalid)?;
    let message_key = digest_parts([
        request.idempotency_key.as_bytes(),
        request.delivery_id.as_bytes(),
        request.attempt_id.as_bytes(),
    ]);
    let message_id = format!(
        "<{}@{}>",
        &message_key[DIGEST_PREFIX.len()..],
        config.message_id_domain
    );
    let message = Message::builder()
        .from(Mailbox::new(config.from_name.clone(), sender))
        .to(Mailbox::new(None, recipient))
        .subject(request.message.subject.clone())
        .message_id(Some(message_id.clone()))
        .user_agent("lenso-email-smtp-plugin/0.1".to_owned())
        .multipart(
            MultiPart::alternative()
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_PLAIN)
                        .body(request.message.text.clone()),
                )
                .singlepart(
                    SinglePart::builder()
                        .header(ContentType::TEXT_HTML)
                        .body(request.message.html.clone()),
                ),
        )
        .map_err(|_| PrepareError::Invalid)?;

    Ok(PreparedDispatch {
        message,
        message_id,
        idempotency_key_hash: digest_text(&request.idempotency_key),
        delivery_id_hash: digest_text(&request.delivery_id),
        attempt_id_hash: digest_text(&request.attempt_id),
        request_fingerprint: request_fingerprint(request),
    })
}

fn observed_at() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub(crate) fn unknown_response(provider: &str, code: &str) -> email::DispatchResponse {
    email::DispatchResponse {
        failure: Some(email::DispatchResponseFailure {
            classification: "delivery_unknown".to_owned(),
            code: code.to_owned(),
            retry_after_ms: None,
        }),
        observed_at: observed_at(),
        outcome: email::DispatchResponseOutcome::DeliveryUnknown,
        provider: provider.to_owned(),
        remote_receipt: None,
    }
}

pub(crate) fn temporary_response(
    provider: &str,
    code: &str,
    retry_after_ms: i64,
) -> email::DispatchResponse {
    email::DispatchResponse {
        failure: Some(email::DispatchResponseFailure {
            classification: "temporary_failure".to_owned(),
            code: code.to_owned(),
            retry_after_ms: Some(retry_after_ms),
        }),
        observed_at: observed_at(),
        outcome: email::DispatchResponseOutcome::TemporaryFailure,
        provider: provider.to_owned(),
        remote_receipt: None,
    }
}

fn permanent_response(provider: &str, code: &str) -> email::DispatchResponse {
    email::DispatchResponse {
        failure: Some(email::DispatchResponseFailure {
            classification: "permanent_failure".to_owned(),
            code: code.to_owned(),
            retry_after_ms: None,
        }),
        observed_at: observed_at(),
        outcome: email::DispatchResponseOutcome::PermanentFailure,
        provider: provider.to_owned(),
        remote_receipt: None,
    }
}

fn accepted_response(
    provider: &str,
    message_id: &str,
    response: &SmtpResponse,
) -> email::DispatchResponse {
    let code = response.code().to_string();
    let lines = response.message().collect::<Vec<_>>().join("\n");
    let digest = digest_parts([code.as_bytes(), lines.as_bytes(), message_id.as_bytes()]);
    email::DispatchResponse {
        failure: None,
        observed_at: observed_at(),
        outcome: email::DispatchResponseOutcome::Accepted,
        provider: provider.to_owned(),
        remote_receipt: Some(email::DispatchResponseRemoteReceipt {
            remote_id: message_id.to_owned(),
            source: "rfc5322-message-id".to_owned(),
            digest,
        }),
    }
}

fn smtp_error_response(provider: &str, error: &SmtpError) -> email::DispatchResponse {
    if error.is_transient() {
        temporary_response(provider, "smtp_transient_response", 60_000)
    } else if error.is_permanent() {
        permanent_response(provider, "smtp_permanent_response")
    } else {
        unknown_response(provider, "smtp_transport_uncertain")
    }
}

pub(crate) async fn send_smtp(
    config: &SmtpConfig,
    username: &Zeroizing<String>,
    password: &Zeroizing<String>,
    prepared: PreparedDispatch,
) -> email::DispatchResponse {
    let builder = match config.tls_mode {
        TlsMode::ImplicitTls => AsyncSmtpTransport::<Tokio1Executor>::relay(&config.smtp_host),
        TlsMode::StarttlsRequired => {
            AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&config.smtp_host)
        }
    };
    let Ok(builder) = builder else {
        return permanent_response(&config.provider, "smtp_configuration_invalid");
    };
    let transport = builder
        .port(config.smtp_port)
        .credentials(Credentials::new(
            username.as_str().to_owned(),
            password.as_str().to_owned(),
        ))
        .timeout(Some(Duration::from_millis(config.command_timeout_ms)))
        .build();
    let timeout = Duration::from_millis(config.command_timeout_ms.saturating_add(1_000));
    match tokio::time::timeout(timeout, transport.send(prepared.message)).await {
        Ok(Ok(response)) if response.is_positive() => {
            accepted_response(&config.provider, &prepared.message_id, &response)
        }
        Ok(Ok(_)) => unknown_response(&config.provider, "smtp_non_positive_completion"),
        Ok(Err(error)) => smtp_error_response(&config.provider, &error),
        Err(_) => unknown_response(&config.provider, "smtp_timeout_unknown"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> SmtpConfig {
        SmtpConfig {
            schema: "smtp".into(),
            database_url_secret: "secret://postgres".into(),
            provider: "smtp-primary".into(),
            smtp_host: "smtp.example.com".into(),
            smtp_port: 465,
            tls_mode: TlsMode::ImplicitTls,
            username_secret_ref: "secret://smtp/user".into(),
            password_secret_ref: "secret://smtp/pass".into(),
            from_address: "hello@example.com".into(),
            from_name: Some("Example".into()),
            message_id_domain: "mail.example.com".into(),
            command_timeout_ms: 10_000,
            effect_lease_ms: 20_000,
            max_message_bytes: 900_000,
            allowed_callers: vec!["notification".into()],
        }
    }

    fn request() -> email::DispatchRequest {
        let mut message = email::DispatchRequestMessage {
            content_digest: String::new(),
            html: "<p>Hello</p>".into(),
            locale: "en-US".into(),
            subject: "Hello".into(),
            template_id: "welcome".into(),
            template_version: "v1".into(),
            text: "Hello".into(),
        };
        message.content_digest = content_digest(&message);
        email::DispatchRequest {
            attempt_id: "attempt_1".into(),
            correlation_id: "story_1".into(),
            delivery_id: "delivery_1".into(),
            idempotency_key: "attempt_1".into(),
            message,
            recipient: email::DispatchRequestRecipient {
                address: "person@example.com".into(),
            },
            run_id: "run_1".into(),
        }
    }

    #[test]
    fn validates_digest_and_builds_stable_message_id_without_recipient() {
        let first = prepare_dispatch(&config(), &request()).unwrap();
        let second = prepare_dispatch(&config(), &request()).unwrap();
        assert_eq!(first.message_id, second.message_id);
        assert!(!first.message_id.contains("person"));
        assert!(!first.request_fingerprint.contains("person"));
    }

    #[test]
    fn rejects_modified_content_before_effect() {
        let mut request = request();
        request.message.html.push_str("changed");
        assert_eq!(
            prepare_dispatch(&config(), &request).unwrap_err(),
            PrepareError::Invalid
        );
    }

    #[test]
    fn response_shapes_match_contract_outcomes() {
        let temporary = temporary_response("smtp", "busy", 1_000);
        assert_eq!(
            temporary.outcome,
            email::DispatchResponseOutcome::TemporaryFailure
        );
        assert!(temporary.remote_receipt.is_none());
        let unknown = unknown_response("smtp", "timeout");
        assert_eq!(
            unknown
                .failure
                .as_ref()
                .map(|failure| failure.classification.as_str()),
            Some("delivery_unknown")
        );
    }
}
