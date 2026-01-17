-- AlterTable
ALTER TABLE "ConversationByUser" ADD COLUMN     "isActive" BOOLEAN NOT NULL DEFAULT true,
ADD COLUMN     "leftAt" TIMESTAMP(3);
