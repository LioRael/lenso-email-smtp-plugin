# Lenso SMTP Email Plugin

`lenso.email.smtp` is a removable, TLS-only SMTP Provider for `lenso.email-dispatch@1`. Notification owns intent, attempts, retry policy, and delivered-state observation; this Plugin owns SMTP credentials, message submission, provider evidence, and a PostgreSQL effect fence.

## Real workflow

1. Notification invokes `dispatch` with one rendered recipient/message snapshot, stable delivery/attempt/run IDs, an idempotency key, and the SHA-256 content digest.
2. The Provider checks the caller Instance, every contract bound, the recipient mailbox, header safety, encoded-size budget, and recomputes the content digest before any external effect.
3. PostgreSQL atomically creates or reads the effect fence. A repeated request with the same identity replays its terminal response; an identity reused for different bytes fails before SMTP.
4. The Plugin resolves SMTP username/password through `lenso.secrets@1`, establishes either implicit TLS or required STARTTLS, and submits a multipart text/HTML message with a deterministic RFC 5322 Message-ID.
5. A positive SMTP completion returns `accepted`. This means the configured relay accepted responsibility for the message; it does **not** mean the recipient mailbox delivered or displayed it.

The Plugin never stores raw recipients, subjects, text, HTML, usernames, or passwords. Its table contains only SHA-256 identities/digests, fence state/timestamps, and the bounded portable response.

## Result semantics

| SMTP observation | Capability outcome | Retry meaning |
| --- | --- | --- |
| Positive relay completion | `accepted` | Notification records accepted, not delivered |
| Explicit 4xx SMTP rejection | `temporary_failure` | Safe for Notification policy to retry |
| Explicit 5xx SMTP rejection | `permanent_failure` | Definitive rejection |
| Timeout, network/TLS/client failure after send starts | `delivery_unknown` | Terminal ambiguity; never silently repeat |
| Credentials unavailable before SMTP | `temporary_failure` | No SMTP effect started |

`invalid_dispatch` and `unsupported_message` are used only for request rejection before an effect begins. After the SMTP future starts, any non-definitive result is a successful response with `delivery_unknown`, never a Domain error.

## Durable idempotency and restart behavior

- The primary identity is `SHA-256(idempotency_key)`; `(SHA-256(delivery_id), SHA-256(attempt_id))` is independently unique to prevent a second key from reopening the same attempt.
- The request fingerprint covers every request field with length-delimited SHA-256 input. Reusing an identity with different content is `invalid_dispatch`.
- One caller changes `prepared` to `sending` with a monotonically increasing fencing token and bounded lease. Concurrent callers wait for the terminal response and never submit a second message.
- A process crash or timeout after the fence is claimed leaves `sending`. Once the lease expires, the next observer atomically records `delivery_unknown`; it does not resend.
- Finalization is fence-checked. A stale sender cannot overwrite an already-closed `delivery_unknown` row.

## Configuration

```json
{
  "schema": "lenso_email_smtp",
  "database_url_secret": "secret://postgres/email-smtp",
  "provider": "smtp-primary",
  "smtp_host": "smtp.example.com",
  "smtp_port": 465,
  "tls_mode": "implicit_tls",
  "username_secret_ref": "secret://smtp/username",
  "password_secret_ref": "secret://smtp/password",
  "from_address": "notifications@example.com",
  "from_name": "Example",
  "message_id_domain": "mail.example.com",
  "command_timeout_ms": 30000,
  "effect_lease_ms": 32000,
  "max_message_bytes": 900000,
  "allowed_callers": ["notification"]
}
```

`tls_mode` is either `implicit_tls` or `starttls_required`. Opportunistic and plaintext SMTP are not implemented. `effect_lease_ms` must exceed `command_timeout_ms` by at least 1.5 seconds so an active SMTP future cannot lose its fence before the local timeout resolves.

Run schema setup explicitly before Plugin activation:

```rust,no_run
use lenso_email_smtp_plugin::EmailSmtpOperator;

# async fn setup(database_url: &str) -> Result<(), Box<dyn std::error::Error>> {
EmailSmtpOperator::setup(database_url, "lenso_email_smtp").await?;
# Ok(()) }
```

## Security boundary

- The resolved Plan must provide exactly one `lenso.secrets@1`; the Plugin stores only secret references in configuration.
- Configuration and Plugin `Debug` redact credential references and the sender mailbox. Generated dispatch request `Debug` already redacts recipient and rendered message fields.
- TLS certificate validation uses rustls and web PKI roots. STARTTLS is required rather than opportunistic, preventing downgrade to plaintext.
- No request or SMTP error path logs the recipient, rendered content, or credentials.

## Intentional gaps

V1 sends one recipient with text/HTML alternative bodies. It does not declare attachments, CC/BCC, reply-to, per-message custom headers, DKIM signing, bounce processing, complaint processing, or provider delivery webhooks. Configure DKIM and bounce handling at the SMTP relay. A later delivery-observation Plugin may move Notification from `accepted` to `delivered`; this SMTP Provider does not fabricate that evidence.

## Verification

```bash
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
./scripts/check-repository-boundary.sh
```

The PostgreSQL acceptance test additionally uses `LENSO_EMAIL_SMTP_TEST_DATABASE_URL`; the dedicated database name must start with `lenso_email_smtp_test`.
