use chrono::{DateTime, Utc};
use lenso_capability_email_dispatch as email;
use lenso_kernel::RuntimeFailure;
use lenso_postgres_kit::OwnedPostgres;
use sqlx::Row;
use thiserror::Error;

#[derive(Clone, Debug)]
pub(crate) struct DispatchIdentity {
    pub idempotency_key_hash: String,
    pub delivery_id_hash: String,
    pub attempt_id_hash: String,
    pub request_fingerprint: String,
    pub content_digest: String,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum BeginDispatch {
    Send { fence: i64 },
    Replay(email::DispatchResponse),
    InFlight { remaining_ms: i64 },
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum EffectStatus {
    Final(email::DispatchResponse),
    InFlight { remaining_ms: i64 },
}

#[derive(Debug, Error)]
pub(crate) enum StorageError {
    #[error("dispatch identity conflicts with an existing effect fence")]
    Conflict,
    #[error("SMTP effect storage runtime failure")]
    Runtime(RuntimeFailure),
}

impl From<RuntimeFailure> for StorageError {
    fn from(value: RuntimeFailure) -> Self {
        Self::Runtime(value)
    }
}

fn runtime(operation: &str, error: impl std::fmt::Display) -> StorageError {
    RuntimeFailure::PluginFailure {
        detail: format!("SMTP effect storage failed to {operation}: {error}"),
    }
    .into()
}

fn decode_response(value: serde_json::Value) -> Result<email::DispatchResponse, StorageError> {
    serde_json::from_value(value).map_err(|error| runtime("decode a stored response", error))
}

pub(crate) async fn begin_dispatch(
    postgres: &OwnedPostgres,
    identity: &DispatchIdentity,
    lease_ms: i64,
    expired_response: &email::DispatchResponse,
) -> Result<BeginDispatch, StorageError> {
    let mut transaction = postgres
        .pool()
        .begin()
        .await
        .map_err(|error| runtime("begin a dispatch fence transaction", error))?;
    sqlx::query(
        "INSERT INTO smtp_dispatch_effects(idempotency_key_hash,delivery_id_hash,attempt_id_hash,request_fingerprint,content_digest,state) VALUES($1,$2,$3,$4,$5,'prepared') ON CONFLICT DO NOTHING",
    )
    .bind(&identity.idempotency_key_hash)
    .bind(&identity.delivery_id_hash)
    .bind(&identity.attempt_id_hash)
    .bind(&identity.request_fingerprint)
    .bind(&identity.content_digest)
    .execute(&mut *transaction)
    .await
    .map_err(|error| runtime("insert a dispatch fence", error))?;

    let row = sqlx::query(
        "SELECT request_fingerprint,content_digest,state,fence,lease_expires_at,response,clock_timestamp() AS database_now FROM smtp_dispatch_effects WHERE idempotency_key_hash=$1 FOR UPDATE",
    )
    .bind(&identity.idempotency_key_hash)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|error| runtime("lock a dispatch fence", error))?;
    let Some(row) = row else {
        let collides = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM smtp_dispatch_effects WHERE delivery_id_hash=$1 AND attempt_id_hash=$2)",
        )
        .bind(&identity.delivery_id_hash)
        .bind(&identity.attempt_id_hash)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|error| runtime("resolve an attempt identity collision", error))?;
        transaction
            .rollback()
            .await
            .map_err(|error| runtime("roll back an identity collision", error))?;
        return if collides {
            Err(StorageError::Conflict)
        } else {
            Err(runtime(
                "resolve a dispatch fence",
                "inserted row is absent",
            ))
        };
    };

    let request_fingerprint: String = row
        .try_get("request_fingerprint")
        .map_err(|error| runtime("decode a request fingerprint", error))?;
    let content_digest: String = row
        .try_get("content_digest")
        .map_err(|error| runtime("decode a content digest", error))?;
    if request_fingerprint != identity.request_fingerprint
        || content_digest != identity.content_digest
    {
        transaction
            .rollback()
            .await
            .map_err(|error| runtime("roll back a conflicting dispatch", error))?;
        return Err(StorageError::Conflict);
    }

    let state: String = row
        .try_get("state")
        .map_err(|error| runtime("decode a dispatch state", error))?;
    let result = match state.as_str() {
        "prepared" => {
            let fence: i64 = row
                .try_get("fence")
                .map_err(|error| runtime("decode a dispatch fence", error))?;
            let next_fence = fence
                .checked_add(1)
                .ok_or_else(|| runtime("advance a dispatch fence", "fence exhausted"))?;
            let updated = sqlx::query(
                "UPDATE smtp_dispatch_effects SET state='sending',fence=$2,effect_started_at=clock_timestamp(),lease_expires_at=clock_timestamp()+($3 * interval '1 millisecond'),updated_at=clock_timestamp() WHERE idempotency_key_hash=$1 AND state='prepared' AND fence=$4",
            )
            .bind(&identity.idempotency_key_hash)
            .bind(next_fence)
            .bind(lease_ms)
            .bind(fence)
            .execute(&mut *transaction)
            .await
            .map_err(|error| runtime("claim a dispatch fence", error))?;
            if updated.rows_affected() != 1 {
                return Err(runtime("claim a dispatch fence", "compare-and-set failed"));
            }
            BeginDispatch::Send { fence: next_fence }
        }
        "sending" => {
            let lease_expires_at: DateTime<Utc> = row
                .try_get("lease_expires_at")
                .map_err(|error| runtime("decode a dispatch lease", error))?;
            let database_now: DateTime<Utc> = row
                .try_get("database_now")
                .map_err(|error| runtime("decode the database clock", error))?;
            if lease_expires_at <= database_now {
                let response = serde_json::to_value(expired_response)
                    .map_err(|error| runtime("encode an expired response", error))?;
                let updated = sqlx::query(
                    "UPDATE smtp_dispatch_effects SET state='delivery_unknown',response=$2,lease_expires_at=NULL,updated_at=clock_timestamp() WHERE idempotency_key_hash=$1 AND state='sending' AND lease_expires_at<=clock_timestamp()",
                )
                .bind(&identity.idempotency_key_hash)
                .bind(response)
                .execute(&mut *transaction)
                .await
                .map_err(|error| runtime("close an expired dispatch", error))?;
                if updated.rows_affected() != 1 {
                    return Err(runtime(
                        "close an expired dispatch",
                        "lease compare-and-set failed",
                    ));
                }
                BeginDispatch::Replay(expired_response.clone())
            } else {
                BeginDispatch::InFlight {
                    remaining_ms: (lease_expires_at - database_now).num_milliseconds().max(0),
                }
            }
        }
        "accepted" | "temporary_failure" | "permanent_failure" | "delivery_unknown" => {
            let response: serde_json::Value = row
                .try_get("response")
                .map_err(|error| runtime("decode a final response", error))?;
            BeginDispatch::Replay(decode_response(response)?)
        }
        _ => return Err(runtime("decode a dispatch state", "unknown state")),
    };
    transaction
        .commit()
        .await
        .map_err(|error| runtime("commit a dispatch fence", error))?;
    Ok(result)
}

pub(crate) async fn effect_status(
    postgres: &OwnedPostgres,
    idempotency_key_hash: &str,
) -> Result<EffectStatus, StorageError> {
    let row = sqlx::query(
        "SELECT state,response,GREATEST(0,(EXTRACT(EPOCH FROM (lease_expires_at-clock_timestamp()))*1000)::bigint) AS remaining_ms FROM smtp_dispatch_effects WHERE idempotency_key_hash=$1",
    )
    .bind(idempotency_key_hash)
    .fetch_optional(postgres.pool())
    .await
    .map_err(|error| runtime("read a dispatch fence", error))?
    .ok_or_else(|| runtime("read a dispatch fence", "row is absent"))?;
    let state: String = row
        .try_get("state")
        .map_err(|error| runtime("decode a dispatch state", error))?;
    if state == "sending" {
        return Ok(EffectStatus::InFlight {
            remaining_ms: row
                .try_get("remaining_ms")
                .map_err(|error| runtime("decode a dispatch lease", error))?,
        });
    }
    let response: serde_json::Value = row
        .try_get("response")
        .map_err(|error| runtime("decode a final response", error))?;
    Ok(EffectStatus::Final(decode_response(response)?))
}

pub(crate) async fn finalize_dispatch(
    postgres: &OwnedPostgres,
    idempotency_key_hash: &str,
    fence: i64,
    response: &email::DispatchResponse,
) -> Result<email::DispatchResponse, StorageError> {
    let state = match response.outcome {
        email::DispatchResponseOutcome::Accepted => "accepted",
        email::DispatchResponseOutcome::TemporaryFailure => "temporary_failure",
        email::DispatchResponseOutcome::PermanentFailure => "permanent_failure",
        email::DispatchResponseOutcome::DeliveryUnknown => "delivery_unknown",
    };
    let response_json = serde_json::to_value(response)
        .map_err(|error| runtime("encode a final response", error))?;
    let updated = sqlx::query(
        "UPDATE smtp_dispatch_effects SET state=$3,response=$4,lease_expires_at=NULL,updated_at=transaction_timestamp() WHERE idempotency_key_hash=$1 AND state='sending' AND fence=$2",
    )
    .bind(idempotency_key_hash)
    .bind(fence)
    .bind(state)
    .bind(response_json)
    .execute(postgres.pool())
    .await
    .map_err(|error| runtime("finalize a dispatch fence", error))?;
    if updated.rows_affected() == 1 {
        return Ok(response.clone());
    }
    match effect_status(postgres, idempotency_key_hash).await? {
        EffectStatus::Final(stored) => Ok(stored),
        EffectStatus::InFlight { .. } => Err(runtime(
            "finalize a dispatch fence",
            "fence was lost while the effect remains active",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_debug_contains_only_hashes() {
        let identity = DispatchIdentity {
            idempotency_key_hash: format!("sha256:{}", "a".repeat(64)),
            delivery_id_hash: format!("sha256:{}", "b".repeat(64)),
            attempt_id_hash: format!("sha256:{}", "c".repeat(64)),
            request_fingerprint: format!("sha256:{}", "d".repeat(64)),
            content_digest: format!("sha256:{}", "e".repeat(64)),
        };
        let debug = format!("{identity:?}");
        assert!(!debug.contains('@'));
        assert!(!debug.contains("secret"));
    }
}
