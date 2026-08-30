# SMTP Email Plugin card

- **Job:** submit a rendered transactional email to an SMTP relay without allowing retries to duplicate an ambiguous external effect.
- **Provides:** `lenso.email-dispatch@1` (`dispatch`).
- **Requires:** exactly one `lenso.secrets@1`.
- **Owns:** SMTP configuration, credential resolution, TLS transport, provider receipt evidence, and `smtp_dispatch_effects`.
- **Does not own:** notification intent, templates, scheduling, retry policy, delivered-state observation, or raw message persistence.
- **Success proof:** relay-positive completion plus stable RFC 5322 Message-ID; success is `accepted`, never fabricated `delivered`.
- **Ambiguity rule:** network/TLS/client timeout after SMTP starts is terminal `delivery_unknown`.

