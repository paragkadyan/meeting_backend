import { PrismaClient } from "@prisma/client";

export const prisma = new PrismaClient();

export const connectPostgres = async () => {
  try {
    await prisma.$connect();
    console.log("PostgreSQL Connected (Prisma)");
  } catch (err) {
    console.error("PostgreSQL Error:", err);
  }
};
