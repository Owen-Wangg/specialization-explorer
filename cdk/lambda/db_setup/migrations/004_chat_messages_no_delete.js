// Stored chat messages can only disappear together with their chat session.
// Deleting a session cascades to its messages; deleting messages directly, or truncating the table, is rejected.
exports.up = (pgm) => {
  pgm.sql(`
    ALTER TABLE chat_messages DROP CONSTRAINT IF EXISTS fk_chat_messages_chat_session_id;
    ALTER TABLE chat_messages
      ADD CONSTRAINT fk_chat_messages_chat_session_id
      FOREIGN KEY (chat_session_id) REFERENCES chat_sessions(id) ON DELETE CASCADE;

    -- A trigger depth above 1 means the delete was fired by the foreign key cascade, not issued directly
    CREATE OR REPLACE FUNCTION reject_chat_message_delete() RETURNS trigger AS $$
    BEGIN
      IF pg_trigger_depth() > 1 THEN
        RETURN OLD;
      END IF;
      RAISE EXCEPTION 'chat_messages rows can only be deleted with their chat session';
    END;
    $$ LANGUAGE plpgsql;

    CREATE OR REPLACE FUNCTION reject_chat_message_truncate() RETURNS trigger AS $$
    BEGIN
      RAISE EXCEPTION 'chat_messages cannot be truncated';
    END;
    $$ LANGUAGE plpgsql;

    DROP TRIGGER IF EXISTS chat_messages_no_delete ON chat_messages;
    CREATE TRIGGER chat_messages_no_delete
      BEFORE DELETE ON chat_messages
      FOR EACH ROW EXECUTE FUNCTION reject_chat_message_delete();

    DROP TRIGGER IF EXISTS chat_messages_no_truncate ON chat_messages;
    CREATE TRIGGER chat_messages_no_truncate
      BEFORE TRUNCATE ON chat_messages
      FOR EACH STATEMENT EXECUTE FUNCTION reject_chat_message_truncate();
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TRIGGER IF EXISTS chat_messages_no_truncate ON chat_messages;
    DROP TRIGGER IF EXISTS chat_messages_no_delete ON chat_messages;
    DROP FUNCTION IF EXISTS reject_chat_message_truncate();
    DROP FUNCTION IF EXISTS reject_chat_message_delete();

    ALTER TABLE chat_messages DROP CONSTRAINT IF EXISTS fk_chat_messages_chat_session_id;
    ALTER TABLE chat_messages
      ADD CONSTRAINT fk_chat_messages_chat_session_id
      FOREIGN KEY (chat_session_id) REFERENCES chat_sessions(id);
  `);
};
