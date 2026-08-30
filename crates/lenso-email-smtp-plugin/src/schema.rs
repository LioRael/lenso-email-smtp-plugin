use lenso_postgres_kit::{Migration, PlanError, SchemaPlan, sql_migrations};

const MIGRATIONS: &[Migration] = sql_migrations![(
    1,
    "create-smtp-effects",
    "migrations/001_create_smtp_effects.sql"
),];

pub(crate) fn schema_plan(schema: impl Into<std::sync::Arc<str>>) -> Result<SchemaPlan, PlanError> {
    SchemaPlan::new(schema, MIGRATIONS)
}

#[cfg(test)]
mod tests {
    #[test]
    fn migration_contains_effect_fence_without_sensitive_payload_columns() {
        let sql = include_str!("../migrations/001_create_smtp_effects.sql");
        assert!(sql.contains("fence bigint"));
        assert!(sql.contains("lease_expires_at"));
        assert!(sql.contains("UNIQUE (delivery_id_hash, attempt_id_hash)"));
        for forbidden in [
            "recipient text",
            "subject text",
            "html text",
            "password text",
        ] {
            assert!(!sql.contains(forbidden));
        }
    }
}
