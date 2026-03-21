import prisma from "../../db/post";

export interface MediaRecord {
  id: string;
  fileName: string;
  objectKey: string;
  fileType: string;
  mimeType: string;
  size: number;
  chatId: string;
  senderId: string;
  createdAt: Date;
}

export async function initMediaTable(): Promise<void> {
  await prisma.$executeRawUnsafe(`
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
  `);

  await prisma.$executeRawUnsafe(
    `CREATE INDEX IF NOT EXISTS idx_media_files_chat_id ON media_files(chat_id);`
  );
  await prisma.$executeRawUnsafe(
    `CREATE INDEX IF NOT EXISTS idx_media_files_file_name ON media_files(file_name);`
  );
}

export async function createMediaRecord(record: MediaRecord): Promise<void> {
  await prisma.$executeRawUnsafe(
    `INSERT INTO media_files (id, file_name, object_key, file_type, mime_type, size, chat_id, sender_id, created_at)
     VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::uuid, $8::uuid, $9::timestamptz)`,
    record.id,
    record.fileName,
    record.objectKey,
    record.fileType,
    record.mimeType,
    record.size,
    record.chatId,
    record.senderId,
    record.createdAt
  );
}

export async function getMediaById(id: string): Promise<MediaRecord | null> {
  const rows = await prisma.$queryRawUnsafe<MediaRecord[]>(
    `SELECT
      id,
      file_name as "fileName",
      object_key as "objectKey",
      file_type as "fileType",
      mime_type as "mimeType",
      size,
      chat_id as "chatId",
      sender_id as "senderId",
      created_at as "createdAt"
     FROM media_files
     WHERE id = $1::uuid
     LIMIT 1`,
    id
  );

  return rows.length ? rows[0] : null;
}

export async function getMediaByIds(ids: string[]): Promise<MediaRecord[]> {
  if (!ids.length) return [];

  return prisma.$queryRawUnsafe<MediaRecord[]>(
    `SELECT
      id,
      file_name as "fileName",
      object_key as "objectKey",
      file_type as "fileType",
      mime_type as "mimeType",
      size,
      chat_id as "chatId",
      sender_id as "senderId",
      created_at as "createdAt"
     FROM media_files
     WHERE id = ANY($1::uuid[])`,
    ids
  );
}
