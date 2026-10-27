// Stored chat messages are never edited by the application, so reject updates at the database level.
exports.up = (pgm) => {
  pgm.sql(`
    CREATE OR REPLACE FUNCTION reject_chat_message_update() RETURNS trigger AS $$
    BEGIN
      RAISE EXCEPTION 'chat_messages rows cannot be updated';
    END;
    $$ LANGUAGE plpgsql;

    DROP TRIGGER IF EXISTS chat_messages_no_update ON chat_messages;
    CREATE TRIGGER chat_messages_no_update
      BEFORE UPDATE ON chat_messages
      FOR EACH ROW EXECUTE FUNCTION reject_chat_message_update();
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DROP TRIGGER IF EXISTS chat_messages_no_update ON chat_messages;
    DROP FUNCTION IF EXISTS reject_chat_message_update();
  `);
};
