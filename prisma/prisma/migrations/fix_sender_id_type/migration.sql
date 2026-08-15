ALTER TABLE "media_files"
DROP CONSTRAINT IF EXISTS "media_files_sender_id_fkey";

ALTER TABLE "media_files"
ALTER COLUMN "sender_id" TYPE TEXT
USING "sender_id"::TEXT;

ALTER TABLE "media_files"
ADD CONSTRAINT "media_files_sender_id_fkey"
FOREIGN KEY ("sender_id")
REFERENCES "User"("id")
ON DELETE CASCADE
ON UPDATE CASCADE;