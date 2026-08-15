-- AlterTable
ALTER TABLE "ConversationByUser"
ADD COLUMN "deletedAt" TIMESTAMP(3),
ADD COLUMN "deletedMessageId" TEXT;

-- Fix media_files.sender_id: UUID -> TEXT
ALTER TABLE "media_files"
ALTER COLUMN "sender_id" TYPE TEXT
USING "sender_id"::TEXT;

-- AddForeignKey
ALTER TABLE "media_files"
ADD CONSTRAINT "media_files_sender_id_fkey"
FOREIGN KEY ("sender_id")
REFERENCES "User"("id")
ON DELETE CASCADE
ON UPDATE CASCADE;