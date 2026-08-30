use super::*;

use futures::future::join_all;
use sqlx::{AssertSqlSafe, Row};

async fn prepare() -> Option<(String, String, OwnedPostgres)> {
    let database_url = std::env::var("LENSO_EMAIL_SMTP_TEST_DATABASE_URL").ok()?;
    let database_name = database_url
        .split('?')
        .next()
        .and_then(|value| value.rsplit('/').next())
        .unwrap_or_default();
    assert!(
        database_name.starts_with("lenso_email_smtp_test"),
        "acceptance requires a dedicated lenso_email_smtp_test* database"
    );
    let schema_name = format!("smtp_test_{}", uuid_like());
    EmailSmtpOperator::setup(&database_url, &schema_name)
        .await
        .unwrap();
    let postgres = OwnedPostgres::prepare(
        &database_url,
        schema::schema_plan(schema_name.clone()).unwrap(),
    )
    .await
    .unwrap();
    Some((database_url, schema_name, postgres))
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!("{nanos:x}")
}

async fn cleanup(database_url: &str, schema_name: &str, postgres: OwnedPostgres) {
    postgres.pool().close().await;
    let pool = sqlx::PgPool::connect(database_url).await.unwrap();
    sqlx::query(AssertSqlSafe(format!(
        "DROP SCHEMA \"{schema_name}\" CASCADE"
    )))
    .execute(&pool)
    .await
    .unwrap();
    pool.close().await;
}

fn identity(suffix: &str) -> storage::DispatchIdentity {
    storage::DispatchIdentity {
        idempotency_key_hash: transport::digest_text(&format!("idem-{suffix}")),
        delivery_id_hash: transport::digest_text(&format!("delivery-{suffix}")),
        attempt_id_hash: transport::digest_text(&format!("attempt-{suffix}")),
        request_fingerprint: transport::digest_text(&format!("request-{suffix}")),
        content_digest: transport::digest_text(&format!("content-{suffix}")),
    }
}

fn response(outcome: email::DispatchResponseOutcome, code: &str) -> email::DispatchResponse {
    let (classification, retry_after_ms) = match outcome {
        email::DispatchResponseOutcome::TemporaryFailure => {
            (Some("temporary_failure"), Some(1_000))
        }
        email::DispatchResponseOutcome::PermanentFailure => (Some("permanent_failure"), None),
        email::DispatchResponseOutcome::DeliveryUnknown => (Some("delivery_unknown"), None),
        email::DispatchResponseOutcome::Accepted => (None, None),
    };
    email::DispatchResponse {
        failure: classification.map(|classification| email::DispatchResponseFailure {
            classification: classification.to_owned(),
            code: code.to_owned(),
            retry_after_ms,
        }),
        observed_at: "2026-08-30T00:00:00Z".to_owned(),
        outcome,
        provider: "smtp-test".to_owned(),
        remote_receipt: None,
    }
}

#[tokio::test]
async fn restart_concurrency_conflict_fencing_and_sensitive_data_absence() {
    let Some((database_url, schema_name, postgres)) = prepare().await else {
        eprintln!("skipping PostgreSQL acceptance; LENSO_EMAIL_SMTP_TEST_DATABASE_URL is unset");
        return;
    };
    let unknown = response(
        email::DispatchResponseOutcome::DeliveryUnknown,
        "lease_expired",
    );

    let concurrent = identity("concurrent");
    let claims =
        join_all((0..8).map(|_| storage::begin_dispatch(&postgres, &concurrent, 30_000, &unknown)))
            .await;
    assert_eq!(
        claims
            .iter()
            .filter(|claim| matches!(claim, Ok(storage::BeginDispatch::Send { .. })))
            .count(),
        1
    );
    assert_eq!(
        claims
            .iter()
            .filter(|claim| matches!(claim, Ok(storage::BeginDispatch::InFlight { .. })))
            .count(),
        7,
        "claims: {claims:?}"
    );
    let fence = claims
        .into_iter()
        .find_map(|claim| match claim.unwrap() {
            storage::BeginDispatch::Send { fence } => Some(fence),
            _ => None,
        })
        .unwrap();
    let accepted = response(email::DispatchResponseOutcome::Accepted, "accepted");
    storage::finalize_dispatch(
        &postgres,
        &concurrent.idempotency_key_hash,
        fence,
        &accepted,
    )
    .await
    .unwrap();
    assert_eq!(
        storage::begin_dispatch(&postgres, &concurrent, 30_000, &unknown)
            .await
            .unwrap(),
        storage::BeginDispatch::Replay(accepted.clone())
    );

    let mut conflicting = concurrent.clone();
    conflicting.request_fingerprint = transport::digest_text("different-sensitive-request");
    assert!(matches!(
        storage::begin_dispatch(&postgres, &conflicting, 30_000, &unknown).await,
        Err(storage::StorageError::Conflict)
    ));
    let mut colliding_attempt = concurrent.clone();
    colliding_attempt.idempotency_key_hash = transport::digest_text("other-idempotency-key");
    assert!(matches!(
        storage::begin_dispatch(&postgres, &colliding_attempt, 30_000, &unknown).await,
        Err(storage::StorageError::Conflict)
    ));

    let restart = identity("restart");
    let stale_fence = match storage::begin_dispatch(&postgres, &restart, 5, &unknown)
        .await
        .unwrap()
    {
        storage::BeginDispatch::Send { fence } => fence,
        other => panic!("unexpected initial restart claim: {other:?}"),
    };
    postgres.pool().close().await;
    tokio::time::sleep(Duration::from_millis(20)).await;
    let restarted = OwnedPostgres::prepare(
        &database_url,
        schema::schema_plan(schema_name.clone()).unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        storage::begin_dispatch(&restarted, &restart, 5_000, &unknown)
            .await
            .unwrap(),
        storage::BeginDispatch::Replay(unknown.clone())
    );
    assert_eq!(
        storage::finalize_dispatch(
            &restarted,
            &restart.idempotency_key_hash,
            stale_fence,
            &accepted,
        )
        .await
        .unwrap(),
        unknown
    );

    let persisted = sqlx::query(
        "SELECT row_to_json(smtp_dispatch_effects)::text AS encoded FROM smtp_dispatch_effects",
    )
    .fetch_all(restarted.pool())
    .await
    .unwrap()
    .into_iter()
    .map(|row| row.try_get::<String, _>("encoded").unwrap())
    .collect::<Vec<_>>()
    .join("\n");
    for sensitive in [
        "person@example.com",
        "different-sensitive-request",
        "secret-password",
        "<p>private body</p>",
    ] {
        assert!(!persisted.contains(sensitive));
    }

    cleanup(&database_url, &schema_name, restarted).await;
}
