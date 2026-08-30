#!/usr/bin/env bash
set -euo pipefail

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

manifest="crates/lenso-email-smtp-plugin/Cargo.toml"
migration="crates/lenso-email-smtp-plugin/migrations/001_create_smtp_effects.sql"
source_root="crates/lenso-email-smtp-plugin/src"

rg -q 'lenso-capability-email-dispatch\.workspace = true' "$manifest"
rg -q 'lenso-capability-secrets\.workspace = true' "$manifest"
rg -q 'lenso-postgres-kit\.workspace = true' "$manifest"
rg -q 'lenso\.email\.smtp' "$manifest"
rg -q 'lenso\.email-dispatch@1' README.md
rg -q 'delivery_unknown' README.md "$source_root"
rg -q 'fence bigint' "$migration"
rg -q 'UNIQUE \(delivery_id_hash, attempt_id_hash\)' "$migration"
rg -q 'tokio1-rustls' Cargo.toml

if rg -n -i '(recipient|subject|html|password|username)[[:space:]]+(text|varchar|bytea|jsonb)' "$migration"; then
  echo "raw sensitive SMTP fields must not be persisted" >&2
  exit 1
fi

if rg -n '(unencrypted_localhost|builder_dangerous|opportunistic|Tls::None)' "$source_root" Cargo.toml; then
  echo "plaintext or opportunistic SMTP is outside this Provider" >&2
  exit 1
fi

if rg -n '(notification_intents|notification_deliveries|templates|retry_schedules)' "$migration"; then
  echo "Notification-owned state leaked into the SMTP Plugin" >&2
  exit 1
fi

if rg -n '(tracing::|log::|dbg!|println!)' "$source_root" -g '!postgres_tests.rs'; then
  echo "SMTP Provider source must not log request or credential material" >&2
  exit 1
fi

if rg -n 'not_supported' crates README.md docs; then
  echo "descriptor/provider must not advertise stub operations" >&2
  exit 1
fi

echo "repository boundary is SMTP-effect-owned and Notification-storage-neutral"
