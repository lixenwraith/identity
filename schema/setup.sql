-- Provision the identity database on PostgreSQL 18. Run once on the jail as
-- the superuser, with the role's password in a psql variable so it reaches
-- neither this file nor the shell history (schema/README.md):
--
--   psql -X -d postgres -v password="'$(cat identity.db-password)'" -f setup.sql                 # owner mode
--   psql -X -d postgres -v password="'$(cat identity.db-password)'" -v split=true -f setup.sql   # split mode
--
-- Owner mode (default): the login role identity owns schema identity, so it
-- may apply the migrations itself. It has no other right.
--
-- Split mode: the NOLOGIN role identity_owner owns the schema and its tables;
-- identity receives only what each migration grants it, rows to read and
-- write, and can alter nothing.
--
-- Migrations are applied on the jail as the owner, in order, each in one
-- transaction (schema/README.md):
--   psql -X -1 -d identity -c 'SET ROLE identity' -f 001_init.sql          # owner mode
--   psql -X -1 -d identity -c 'SET ROLE identity_owner' -f 001_init.sql    # split mode
--
-- The role authenticates from the node over TLS with SCRAM-SHA-256, which
-- pg_hba.conf admits with one hostssl line; no other TCP client is admitted.
\set ON_ERROR_STOP on
\if :{?split}
\else
\set split false
\endif
\if :{?password}
\else
\echo 'setup.sql: pass the role password as -v password="''<password>''"'
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
