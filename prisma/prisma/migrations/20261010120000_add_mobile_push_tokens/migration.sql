-- CreateTable
CREATE TABLE "mobile_push_tokens" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "token" TEXT NOT NULL,
    "platform" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "mobile_push_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "mobile_push_tokens_token_key" ON "mobile_push_tokens"("token");

-- CreateIndex
CREATE INDEX "mobile_push_tokens_userId_idx" ON "mobile_push_tokens"("userId");

-- AddForeignKey
ALTER TABLE "mobile_push_tokens" ADD CONSTRAINT "mobile_push_tokens_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

