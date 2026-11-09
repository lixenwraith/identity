-- Provision the identity database on PostgreSQL 18, once, as the superuser, the
-- role's password in a psql variable (schema/README.md has the commands):
--   psql -X -d postgres -v password="'<password>'" [-v split=true] -f setup.sql
-- Owner mode: the login role identity owns schema identity and may migrate it.
-- Split mode: NOLOGIN identity_owner owns it; identity only reads and writes rows.
\set ON_ERROR_STOP on
\if :{?split}
\else
\set split false
\endif
\if :{?password}
\else
\echo 'setup.sql: pass the role password as -v password="''<password>''"'
\endif
-- An empty password would create the role with none; refuse it before anything exists.
SELECT length(:password) > 0 AS password_given \gset
\if :password_given
\else
DO $$BEGIN RAISE EXCEPTION 'setup.sql: the password is empty'; END$$;
\endif

-- The verifier PostgreSQL stores is SCRAM, whatever the server default says.
SET password_encryption = 'scram-sha-256';

CREATE ROLE identity LOGIN PASSWORD :password
	NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
	CONNECTION LIMIT 12;

-- The builtin C.UTF-8 provider gives code-point ordering and Unicode case
-- mapping that do not change with operating-system library upgrades.
CREATE DATABASE identity
	OWNER postgres
	TEMPLATE template0
	ENCODING 'UTF8'
	LOCALE_PROVIDER builtin
	BUILTIN_LOCALE 'C.UTF-8';

REVOKE ALL ON DATABASE identity FROM PUBLIC;
GRANT CONNECT ON DATABASE identity TO identity;

\connect identity

-- Nothing may be created in or read from public; identity lives in its own schema.
REVOKE ALL ON SCHEMA public FROM PUBLIC;

\if :split
CREATE ROLE identity_owner NOLOGIN
	NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE SCHEMA identity AUTHORIZATION identity_owner;
GRANT USAGE ON SCHEMA identity TO identity;
\else
CREATE SCHEMA identity AUTHORIZATION identity;
\endif

-- Resolve unqualified names in the identity schema without a URL parameter.
ALTER ROLE identity IN DATABASE identity SET search_path = identity;
-- Bound runaway statements, lock waits and abandoned transactions. The
-- service's own per-request deadlines are shorter.
ALTER ROLE identity IN DATABASE identity SET statement_timeout = '30s';
ALTER ROLE identity IN DATABASE identity SET lock_timeout = '10s';
ALTER ROLE identity IN DATABASE identity SET idle_in_transaction_session_timeout = '60s';
