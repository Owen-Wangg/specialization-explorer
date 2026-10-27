// Per-user random credential for anonymous users. Only a SHA-256 hash is stored; clearing
// user_key_hash revokes the key, and user_key_version records each rotation.
// Existing users have no hash, so their old derived keys stop working and the client creates a new user.
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE users
      ADD COLUMN IF NOT EXISTS user_key_hash varchar,
      ADD COLUMN IF NOT EXISTS user_key_version integer NOT NULL DEFAULT 1;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    ALTER TABLE users
      DROP COLUMN IF EXISTS user_key_hash,
      DROP COLUMN IF EXISTS user_key_version;
  `);
};
