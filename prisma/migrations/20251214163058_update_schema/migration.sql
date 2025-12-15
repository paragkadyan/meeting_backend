-- CreateEnum
CREATE TYPE "UserType" AS ENUM ('REGULAR', 'PREMIUM');

-- CreateEnum
CREATE TYPE "ConvoType" AS ENUM ('DIRECT', 'GROUP');

-- CreateEnum
CREATE TYPE "MemberRole" AS ENUM ('MEMBER', 'ADMIN');

-- CreateEnum
CREATE TYPE "AuthProvider" AS ENUM ('LOCAL', 'GOOGLE');

-- CreateTable
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "password" TEXT,
    "name" TEXT,
    "profileURL" TEXT,
    "mobileNumber" TEXT,
    "googleId" TEXT,
    "location" TEXT,
    "dob" TIMESTAMP(3),
    "refreshToken" TEXT,
    "authProvider" "AuthProvider" NOT NULL DEFAULT 'LOCAL',
    "userType" "UserType" NOT NULL DEFAULT 'REGULAR',
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "paymentID" TEXT,

    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Convo" (
    "id" TEXT NOT NULL,
    "type" "ConvoType" NOT NULL,
    "title" TEXT,
    "theme" TEXT,
    "createdBy" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "profileURL" TEXT,

    CONSTRAINT "Convo_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ConvoMember" (
    "convoID" TEXT NOT NULL,
    "userID" TEXT NOT NULL,
    "role" "MemberRole" NOT NULL DEFAULT 'MEMBER',

    CONSTRAINT "ConvoMember_pkey" PRIMARY KEY ("convoID","userID")
);

-- CreateTable
CREATE TABLE "Feedback" (
    "id" TEXT NOT NULL,
    "userID" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "details" TEXT NOT NULL,
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Feedback_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Payment" (
    "id" TEXT NOT NULL,
    "userID" TEXT NOT NULL,
    "startTime" TIMESTAMP(3),
    "endTime" TIMESTAMP(3),
    "timestamp" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "Payment_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "User_email_key" ON "User"("email");

-- CreateIndex
CREATE UNIQUE INDEX "User_mobileNumber_key" ON "User"("mobileNumber");

-- CreateIndex
CREATE UNIQUE INDEX "User_googleId_key" ON "User"("googleId");

-- CreateIndex
CREATE UNIQUE INDEX "User_paymentID_key" ON "User"("paymentID");

-- CreateIndex
CREATE INDEX "User_email_idx" ON "User"("email");

-- CreateIndex
CREATE INDEX "User_mobileNumber_idx" ON "User"("mobileNumber");

-- CreateIndex
CREATE INDEX "Convo_createdBy_idx" ON "Convo"("createdBy");

-- CreateIndex
CREATE INDEX "ConvoMember_userID_idx" ON "ConvoMember"("userID");

-- CreateIndex
CREATE INDEX "Feedback_userID_idx" ON "Feedback"("userID");

-- CreateIndex
CREATE INDEX "Payment_userID_idx" ON "Payment"("userID");

-- AddForeignKey
ALTER TABLE "Convo" ADD CONSTRAINT "Convo_createdBy_fkey" FOREIGN KEY ("createdBy") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ConvoMember" ADD CONSTRAINT "ConvoMember_convoID_fkey" FOREIGN KEY ("convoID") REFERENCES "Convo"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ConvoMember" ADD CONSTRAINT "ConvoMember_userID_fkey" FOREIGN KEY ("userID") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Feedback" ADD CONSTRAINT "Feedback_userID_fkey" FOREIGN KEY ("userID") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "Payment" ADD CONSTRAINT "Payment_userID_fkey" FOREIGN KEY ("userID") REFERENCES "User"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
