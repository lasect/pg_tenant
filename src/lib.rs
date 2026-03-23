use pgrx::prelude::*;
use std::ffi::CString;
use std::sync::Mutex;

::pgrx::pg_module_magic!(name, version);

/// Static storage for tenant ID as CString
/// UUID string representation (36 bytes) + null terminator
static TENANT_ID_STORAGE: Mutex<Option<CString>> = Mutex::new(None);

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
