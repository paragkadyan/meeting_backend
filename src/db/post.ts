import { PrismaClient } from '../../generated/prisma/client';

import { PrismaPg } from '@prisma/adapter-pg'

const connectionString = `${process.env.DATABASE_URL}`

const adapter = new PrismaPg({ connectionString })
export const prisma = new PrismaClient({ adapter })

export const connectPostgres = async () => {
  try {
    await prisma.$connect();
    console.log("PostgreSQL Connected (Prisma)");
  } catch (err) {
    console.error("PostgreSQL Error:", err);
  }
};

export default prisma;
