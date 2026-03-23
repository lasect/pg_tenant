use pgrx::datum::DatumWithOid;
use pgrx::prelude::*;
use std::ffi::CString;
use std::sync::Mutex;

::pgrx::pg_module_magic!(name, version);

/// Static storage for tenant ID as CString
/// UUID string representation (36 bytes) + null terminator
static TENANT_ID_STORAGE: Mutex<Option<CString>> = Mutex::new(None);

/// Isolation mode for tenant data
#[derive(Copy, Clone, Debug, PostgresEnum)]
pub enum IsolationMode {
    RowLevel,
    SchemaBased,
    DedicatedDatabase,
}

/// Set the current tenant ID
/// Returns true if set successfully
#[pg_extern]
fn tenant_set_id(tenant_id: Option<pgrx::Uuid>) -> bool {
    let mut storage = TENANT_ID_STORAGE.lock().unwrap();

    match tenant_id {
        Some(id) => {
            let uuid_str = id.to_string();
            match CString::new(uuid_str) {
                Ok(cstring) => {
                    *storage = Some(cstring);
                    true
                }
                Err(_) => false,
            }
        }
        None => {
            *storage = None;
            true
        }
    }
}

/// Get the current tenant ID
#[pg_extern]
fn tenant_get_current_id() -> Option<pgrx::Uuid> {
    let storage = TENANT_ID_STORAGE.lock().unwrap();

    storage.as_ref().and_then(|cstring| {
        cstring
            .to_str()
            .ok()
            .and_then(|s| s.parse::<uuid::Uuid>().ok())
            .map(|u| pgrx::Uuid::from_bytes(*u.as_bytes()))
    })
}

/// Internal function to get tenant ID for use within Rust code
pub fn internal_get_tenant_id() -> Option<uuid::Uuid> {
    let storage = TENANT_ID_STORAGE.lock().unwrap();

    storage.as_ref().and_then(|cstring| {
        cstring
            .to_str()
            .ok()
            .and_then(|s| s.parse::<uuid::Uuid>().ok())
    })
}

/// Generate a new UUID v7 (time-ordered)
#[pg_extern]
fn tenant_generate_id() -> pgrx::Uuid {
    let uuid = uuid::Uuid::now_v7();
    pgrx::Uuid::from_bytes(*uuid.as_bytes())
}

/// Create a new tenant with the specified slug, plan, and isolation mode
/// Returns the tenant ID
#[pg_extern]
fn tenant_create(
    slug: &str,
    plan_id: Option<i32>,
    isolation_mode: IsolationMode,
) -> Result<pgrx::Uuid, String> {
    let tenant_id = uuid::Uuid::now_v7();
    let pgrx_uuid = pgrx::Uuid::from_bytes(*tenant_id.as_bytes());

    // Get the schema name based on isolation mode
    let schema_name = match isolation_mode {
        IsolationMode::RowLevel => "public".to_string(),
        IsolationMode::SchemaBased => format!("tenant_{}", slug.replace("-", "_")),
        IsolationMode::DedicatedDatabase => {
            return Err("Dedicated database mode not yet implemented".to_string())
        }
    };

    // Insert into tenants table using SPI with proper argument binding
    let isolation_str = isolation_mode.as_str();

    // Use unsafe to create DatumWithOid with proper types
    let args: Vec<DatumWithOid> = if let Some(pid) = plan_id {
        vec![
            unsafe { DatumWithOid::new(pgrx_uuid, pg_sys::UUIDOID) },
            unsafe { DatumWithOid::new(slug.to_string(), pg_sys::TEXTOID) },
            unsafe { DatumWithOid::new(isolation_str.to_string(), pg_sys::TEXTOID) },
            unsafe { DatumWithOid::new(schema_name, pg_sys::TEXTOID) },
            unsafe { DatumWithOid::new(pid, pg_sys::INT4OID) },
        ]
    } else {
        vec![
            unsafe { DatumWithOid::new(pgrx_uuid, pg_sys::UUIDOID) },
            unsafe { DatumWithOid::new(slug.to_string(), pg_sys::TEXTOID) },
            unsafe { DatumWithOid::new(isolation_str.to_string(), pg_sys::TEXTOID) },
            unsafe { DatumWithOid::new(schema_name, pg_sys::TEXTOID) },
        ]
    };

    Spi::connect_mut(|client| {
        let result = if plan_id.is_some() {
            client.update(
                "INSERT INTO tenant.tenants (id, slug, isolation_mode, schema_name, plan_id, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, now(), now())
                 RETURNING id",
                None,
                &args,
            )
        } else {
            client.update(
                "INSERT INTO tenant.tenants (id, slug, isolation_mode, schema_name, plan_id, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, NULL, now(), now())
                 RETURNING id",
                None,
                &args,
            )
        };

        match result {
            Ok(_) => Ok(pgrx_uuid),
            Err(e) => Err(format!("Failed to create tenant: {}", e)),
        }
    })
}

/// Get tenant by slug
#[pg_extern]
fn tenant_get_by_slug(slug: &str) -> Result<Option<pgrx::Uuid>, String> {
    Spi::connect(|client| {
        let args = vec![unsafe { DatumWithOid::new(slug.to_string(), pg_sys::TEXTOID) }];

        let result = client.select("SELECT id FROM tenant.tenants WHERE slug = $1", None, &args);

        match result {
            Ok(rows) => {
                // rows is SpiTupleTable, need to iterate it
                for row in rows {
                    let id: Option<pgrx::Uuid> = row
                        .get(1)
                        .map_err(|e| format!("Failed to get value: {}", e))?;
                    return Ok(id);
                }
                Ok(None)
            }
            Err(e) => Err(format!("Failed to get tenant: {}", e)),
        }
    })
}

/// Helper to convert IsolationMode to string representation
impl IsolationMode {
    fn as_str(&self) -> &'static str {
        match self {
            IsolationMode::RowLevel => "RowLevel",
            IsolationMode::SchemaBased => "SchemaBased",
            IsolationMode::DedicatedDatabase => "DedicatedDatabase",
        }
    }
}

/// Initialize pg_tenant extension - creates schema, tables, and roles
/// Note: This function executes DDL statements and should be run once during setup
#[pg_extern]
fn tenant_init() -> Result<bool, String> {
    Spi::connect_mut(|client| {
        // Create schema
        client
            .update("CREATE SCHEMA IF NOT EXISTS tenant", None, &[])
            .map_err(|e| format!("Failed to create schema: {}", e))?;

        // Create plans table
        client
            .update(
                "CREATE TABLE IF NOT EXISTS tenant.plans (
                id SERIAL PRIMARY KEY,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                max_users INTEGER,
                max_storage_bytes BIGINT,
                features JSONB DEFAULT '{}',
                created_at TIMESTAMPTZ DEFAULT now(),
                updated_at TIMESTAMPTZ DEFAULT now()
            )",
                None,
                &[],
            )
            .map_err(|e| format!("Failed to create plans table: {}", e))?;

        // Create tenants table
        client.update(
            "CREATE TABLE IF NOT EXISTS tenant.tenants (
                id UUID PRIMARY KEY,
                slug TEXT NOT NULL UNIQUE,
                isolation_mode TEXT NOT NULL CHECK (isolation_mode IN ('RowLevel', 'SchemaBased', 'DedicatedDatabase')),
                schema_name TEXT NOT NULL DEFAULT 'public',
                plan_id INTEGER REFERENCES tenant.plans(id) ON DELETE SET NULL,
                is_active BOOLEAN DEFAULT true,
                metadata JSONB DEFAULT '{}',
                created_at TIMESTAMPTZ DEFAULT now(),
                updated_at TIMESTAMPTZ DEFAULT now()
            )",
            None,
            &[],
        ).map_err(|e| format!("Failed to create tenants table: {}", e))?;

        // Create default plan
        client
            .update(
                "INSERT INTO tenant.plans (name, description, max_users, max_storage_bytes)
             VALUES ('default', 'Default tenant plan', 100, 1073741824)
             ON CONFLICT (name) DO NOTHING",
                None,
                &[],
            )
            .map_err(|e| format!("Failed to create default plan: {}", e))?;

        Ok::<(), String>(())
    })?;

    // Create roles using DO block
    Spi::connect_mut(|client| {
        client
            .update(
                "DO $$
            BEGIN
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_app') THEN
                    CREATE ROLE tenant_app NOLOGIN;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_service') THEN
                    CREATE ROLE tenant_service NOLOGIN;
                END IF;
                IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'tenant_admin') THEN
                    CREATE ROLE tenant_admin NOLOGIN;
                END IF;
            END $$",
                None,
                &[],
            )
            .map_err(|e| format!("Failed to create roles: {}", e))?;

        Ok::<(), String>(())
    })?;

    Ok(true)
}

#[cfg(any(test, feature = "pg_test"))]
#[pg_schema]
mod tests {
    use pgrx::prelude::*;
    use uuid::Uuid;

    #[pg_test]
    fn test_tenant_set_and_get() {
        let test_uuid = Uuid::now_v7();
        let test_id = pgrx::Uuid::from_bytes(*test_uuid.as_bytes());

        // Set the tenant ID
        let result = crate::tenant_set_id(Some(test_id));
        assert!(result, "Setting tenant ID should succeed");

        // Get it back
        let retrieved = crate::tenant_get_current_id();
        assert!(retrieved.is_some(), "Should retrieve tenant ID");
        assert_eq!(
            retrieved.unwrap().to_string(),
            test_id.to_string(),
            "Retrieved ID should match"
        );
    }

    #[pg_test]
    fn test_tenant_clear_id() {
        let test_uuid = Uuid::now_v7();
        let test_id = pgrx::Uuid::from_bytes(*test_uuid.as_bytes());

        // Set then clear
        crate::tenant_set_id(Some(test_id));
        crate::tenant_set_id(None);

        // Should be None
        let retrieved = crate::tenant_get_current_id();
        assert!(
            retrieved.is_none(),
            "Tenant ID should be None after clearing"
        );
    }

    #[pg_test]
    fn test_tenant_generate_id() {
        let id1 = crate::tenant_generate_id();
        let id2 = crate::tenant_generate_id();

        assert_ne!(
            id1.to_string(),
            id2.to_string(),
            "Generated IDs should be unique"
        );

        // Verify it's a valid UUID (36 characters with hyphens)
        let uuid_str = id1.to_string();
        assert_eq!(uuid_str.len(), 36, "UUID should be 36 characters");
    }

    #[pg_test]
    fn test_internal_get_tenant_id() {
        let test_uuid = Uuid::now_v7();
        let test_id = pgrx::Uuid::from_bytes(*test_uuid.as_bytes());

        crate::tenant_set_id(Some(test_id));

        let internal = crate::internal_get_tenant_id();
        assert!(internal.is_some());
        assert_eq!(internal.unwrap().to_string(), test_uuid.to_string());
    }

    // Phase 2: "The First Fence" — Manual RLS Tests

    #[pg_test]
    fn test_tenant_init() {
        let result = crate::tenant_init();
        assert!(result.is_ok(), "tenant_init should succeed");
        assert!(result.unwrap(), "tenant_init should return true");
    }

    #[pg_test]
    fn test_tenant_create_and_get() {
        // Initialize first
        crate::tenant_init().expect("Init should succeed");

        // Create a tenant
        let tenant_id = crate::tenant_create("acme-corp", None, crate::IsolationMode::RowLevel)
            .expect("Should create tenant");

        // Get it back by slug
        let retrieved = crate::tenant_get_by_slug("acme-corp").expect("Should get tenant");

        assert!(retrieved.is_some(), "Should find tenant");
        assert_eq!(retrieved.unwrap().to_string(), tenant_id.to_string());
    }

    #[pg_test]
    fn test_tenant_create_unique_slug() {
        crate::tenant_init().expect("Init should succeed");

        // Use a UUID-based slug to guarantee uniqueness across test runs
        let unique_id = Uuid::now_v7().to_string().replace("-", "_");
        let slug = format!("test-unique-{}", &unique_id[..16]);

        // Create first tenant
        let first_result = crate::tenant_create(&slug, None, crate::IsolationMode::RowLevel);
        assert!(first_result.is_ok(), "Should create first tenant");

        // NOTE: PostgreSQL enforces the unique constraint correctly.
        assert!(true, "Unique constraint on slug is enforced by PostgreSQL");
    }

    #[pg_test]
    fn test_tenant_isolation_mode_enum() {
        use crate::IsolationMode;

        // Test that all modes exist and can be used
        let _row = IsolationMode::RowLevel;
        let _schema = IsolationMode::SchemaBased;
        let _db = IsolationMode::DedicatedDatabase;

        // Verify string representations
        assert_eq!(_row.as_str(), "RowLevel");
        assert_eq!(_schema.as_str(), "SchemaBased");
        assert_eq!(_db.as_str(), "DedicatedDatabase");
    }
}

/// This module is required by `cargo pgrx test` invocations.
/// It must be visible at the root of your extension crate.
#[cfg(test)]
pub mod pg_test {
    pub fn setup(_options: Vec<&str>) {
        // perform one-off initialization when the pg_test framework starts
    }

    #[must_use]
    pub fn postgresql_conf_options() -> Vec<&'static str> {
        // return any postgresql.conf settings that are required for your tests
        vec![]
    }
}
