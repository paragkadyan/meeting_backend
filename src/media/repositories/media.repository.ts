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

export async function createMediaRecord(record: MediaRecord): Promise<void> {
  await prisma.mediaFile.create({
    data: {
      id: record.id,
      fileName: record.fileName,
      objectKey: record.objectKey,
      fileType: record.fileType,
      mimeType: record.mimeType,
      size: BigInt(record.size),
      chatId: record.chatId,
      senderId: record.senderId,
      createdAt: record.createdAt,
    },
  });
}

export async function getMediaById(id: string): Promise<MediaRecord | null> {
  const row = await prisma.mediaFile.findUnique({
    where: { id },
  });

  if (!row) return null;
  return {
    id: row.id,
    fileName: row.fileName,
    objectKey: row.objectKey,
    fileType: row.fileType,
    mimeType: row.mimeType,
    size: Number(row.size),
    chatId: row.chatId,
    senderId: row.senderId,
    createdAt: row.createdAt,
  };
}

export async function getMediaByIds(ids: string[]): Promise<MediaRecord[]> {
  if (!ids.length) return [];

  const rows = await prisma.mediaFile.findMany({
    where: { id: { in: ids } },
  });

  return rows.map((row: { id: string; fileName: string; objectKey: string; fileType: string; mimeType: string; size: bigint; chatId: string; senderId: string; createdAt: Date }) => ({
    id: row.id,
    fileName: row.fileName,
    objectKey: row.objectKey,
    fileType: row.fileType,
    mimeType: row.mimeType,
    size: Number(row.size),
    chatId: row.chatId,
    senderId: row.senderId,
    createdAt: row.createdAt,
  }));
}

export async function deleteMediaById(id: string): Promise<void> {
  await prisma.mediaFile.delete({
    where: { id },
  });
}
