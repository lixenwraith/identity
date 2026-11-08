-- Version 1: accounts, their SCRAM verifiers and their sign-ins. Applied in
-- one transaction as the schema's owner, by psql on the jail (schema/README.md)
-- or by the store's Migrate, which runs this same file. A released migration
-- is never edited; the next one follows it.

CREATE TABLE schema_version (
	singleton  boolean PRIMARY KEY DEFAULT true CHECK (singleton),
	version    integer NOT NULL CHECK (version > 0),
	updated_at timestamptz NOT NULL DEFAULT now()
);

-- An account is a lasting name. Names are stored in one spelling, lowercase,
-- so a plain unique constraint is case-insensitive uniqueness; the pattern is
-- the store's NormalizeName. A disabled account keeps its rows and refuses a
-- sign-in; deleting one takes its verifier and sign-ins with it.
CREATE TABLE accounts (
	account_id  uuid PRIMARY KEY,
	name        text NOT NULL,
	created_at  timestamptz NOT NULL DEFAULT now(),
	disabled_at timestamptz,
	CONSTRAINT accounts_name_key UNIQUE (name),
	CONSTRAINT accounts_name_check CHECK (name ~ '^[a-z][a-z0-9_-]{0,31}$')
);

-- The verifier is what the player's device derived with Argon2id and handed
-- over at registration: the salt, the KDF parameters it was derived under and
-- the two SCRAM keys. No password and no salted password is ever stored. One
-- row per account; the operator's reset replaces it.
CREATE TABLE verifiers (
	account_id    uuid PRIMARY KEY REFERENCES accounts (account_id) ON DELETE CASCADE,
	salt          bytea NOT NULL CHECK (octet_length(salt) BETWEEN 16 AND 64),
	argon_time    integer NOT NULL CHECK (argon_time BETWEEN 1 AND 16),
	argon_memory  integer NOT NULL CHECK (argon_memory BETWEEN 8 AND 262144),
	argon_threads smallint NOT NULL CHECK (argon_threads BETWEEN 1 AND 16),
	stored_key    bytea NOT NULL CHECK (octet_length(stored_key) = 32),
	server_key    bytea NOT NULL CHECK (octet_length(server_key) = 32),
	updated_at    timestamptz NOT NULL DEFAULT now()
);

-- A sign-in is one device's standing proof: the SHA-256 of a token of 32
-- random bytes, the token itself held by the device alone, so a copy of this
-- table signs nobody in. It slides over 30 days and is renewed past half its
-- life; the device's name is what the account's owner revokes it by.
CREATE TABLE sign_ins (
	sign_in_id   uuid PRIMARY KEY,
	account_id   uuid NOT NULL REFERENCES accounts (account_id) ON DELETE CASCADE,
	token_hash   bytea NOT NULL,
	device       text NOT NULL CHECK (char_length(device) BETWEEN 1 AND 64),
	created_at   timestamptz NOT NULL DEFAULT now(),
	last_seen_at timestamptz NOT NULL DEFAULT now(),
	expires_at   timestamptz NOT NULL,
	CONSTRAINT sign_ins_token_hash_key UNIQUE (token_hash),
	CONSTRAINT sign_ins_token_hash_check CHECK (octet_length(token_hash) = 32)
);

CREATE INDEX sign_ins_account_id_idx ON sign_ins (account_id, created_at);
CREATE INDEX sign_ins_expires_at_idx ON sign_ins (expires_at);

-- Least privilege: the runtime role reads and writes rows and alters nothing.
-- In owner mode it owns these tables and the grants add nothing; in split
-- mode they are all it has, and the version it may only read.
GRANT SELECT, INSERT, UPDATE, DELETE ON accounts, verifiers, sign_ins TO identity;
GRANT SELECT ON schema_version TO identity;

INSERT INTO schema_version (version) VALUES (1)
	ON CONFLICT (singleton) DO UPDATE SET version = excluded.version, updated_at = now();
