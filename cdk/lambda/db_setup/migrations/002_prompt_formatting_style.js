// Claude 5.5 follows prompts more literally and no longer adds emojis or bold text on its own.
// Add an explicit style line to the active system_instructions and initial_prompt, as a new version
// so any edits already made in the admin editor are kept.
exports.up = (pgm) => {
  pgm.sql(`
    DO $$
    DECLARE
      r record;
      new_content text;
    BEGIN
      FOR r IN
        SELECT DISTINCT ON (type) type, content, character_limit, affects_text_generation
        FROM system_messages
        WHERE type IN ('system_instructions', 'initial_prompt') AND is_active = true
        ORDER BY type, version DESC
      LOOP
        IF position('STYLE:' in r.content) > 0 THEN
          CONTINUE;
        END IF;

        new_content := r.content || chr(10) || CASE r.type::text
          WHEN 'system_instructions' THEN 'STYLE: Be warm and friendly with at most one emoji per message. Use **bold** for specialization names, course codes and your question, and numbered lists for recommendations.'
          ELSE 'STYLE: Open with a wave emoji (👋) and put the question you ask in **bold**.'
        END;

        UPDATE system_messages SET is_active = false WHERE type = r.type AND is_active = true;

        INSERT INTO system_messages (
          type, content, character_limit, version, is_active, affects_text_generation, created_by, created_at
        )
        SELECT
          r.type,
          new_content,
          GREATEST(r.character_limit, length(new_content)),
          COALESCE(MAX(version), 0) + 1,
          true,
          r.affects_text_generation,
          NULL,
          now()
        FROM system_messages
        WHERE type = r.type;
      END LOOP;
    END $$;
  `);
};

exports.down = (pgm) => {
  pgm.sql(`
    DELETE FROM system_messages
    WHERE type IN ('system_instructions', 'initial_prompt')
      AND created_by IS NULL
      AND version > 1
      AND position('STYLE:' in content) > 0;

    UPDATE system_messages sm
    SET is_active = true
    WHERE sm.type IN ('system_instructions', 'initial_prompt')
      AND sm.version = (SELECT MAX(version) FROM system_messages WHERE type = sm.type)
      AND NOT EXISTS (SELECT 1 FROM system_messages WHERE type = sm.type AND is_active = true);
  `);
};
