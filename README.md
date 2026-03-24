# pg_tenant

Multi-tenant data isolation for PostgreSQL.

## What it does

pg_tenant is a PostgreSQL extension that provides tenant isolation through:

- **Row-level security (RLS)** - Tenants can only see their own rows
- **Schema-based isolation** - Each tenant gets their own schema
- **Context management** - Set and enforce the current tenant ID per session

## Installation

Requires PostgreSQL 13+ and [pgrx](https://github.com/tcdi/pgrx).

```bash
cargo pgrx install
```

## Usage

```sql
-- Load the extension
CREATE EXTENSION pg_tenant;

-- Initialize (creates schema, tables, roles)
SELECT tenant_init();

-- Create a tenant
SELECT tenant_create('acme-corp', NULL, 'RowLevel');

-- Set tenant context for the session
SELECT tenant_set_id(tenant_get_by_slug('acme-corp'));

-- All queries now enforce tenant isolation
```

## Isolation Modes

- **RowLevel** - Uses PostgreSQL RLS policies (default)
- **SchemaBased** - Creates a dedicated schema per tenant
- **DedicatedDatabase** - Not yet implemented

## Requirements

- PostgreSQL 13, 14, 15, 16, 17, or 18
- Rust 1.70+
- pgrx 0.17.0

## License

MIT (2026 Lasect)
