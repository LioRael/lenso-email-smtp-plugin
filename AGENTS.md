# Repository boundary

- This repository owns only the `lenso.email.smtp` Provider and its PostgreSQL effect-fence schema.
- It provides `lenso.email-dispatch@1`; it must not own Notification intents, retry schedules, templates, or delivery lifecycle state.
- Never persist or log raw recipient addresses, subjects, text, HTML, SMTP usernames, or SMTP passwords.
- `invalid_dispatch` and `unsupported_message` are pre-effect only. Ambiguity after SMTP starts is always `delivery_unknown`.
- Plaintext and opportunistic STARTTLS are outside the Plugin boundary.
- Run Cargo through `/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo`.

