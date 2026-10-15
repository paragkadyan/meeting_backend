-- CreateEnum
CREATE TYPE "CallType" AS ENUM ('AUDIO', 'VIDEO');

-- AlterTable
ALTER TABLE "Call" ADD COLUMN "type" "CallType" NOT NULL DEFAULT 'AUDIO';
