CREATE TABLE IF NOT EXISTS media_files (
  id UUID PRIMARY KEY,
  file_name TEXT NOT NULL,
  object_key TEXT NOT NULL UNIQUE,
  file_type TEXT NOT NULL,
  mime_type TEXT NOT NULL,
  size BIGINT NOT NULL,
  chat_id UUID NOT NULL,
  sender_id UUID NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_media_files_chat_id ON media_files(chat_id);
CREATE INDEX IF NOT EXISTS idx_media_files_file_name ON media_files(file_name);
