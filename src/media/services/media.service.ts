import { v4 as uuidv4 } from "uuid";
import { createMediaRecord, getMediaById, getMediaByIds, MediaRecord } from "../repositories/media.repository";
import { resolveMediaFolder } from "../utils/fileType";
import { uploadObject, getPresignedGetUrl } from "./storage.service";
import { isUserInChat } from "../repositories/chat.repository";
import { apiError } from "../../utils/apiError";

interface UploadPayload {
  originalName: string;
  mimeType: string;
  size: number;
  buffer: Buffer;
  chatId: string;
  senderId: string;
}

export async function uploadMedia(payload: UploadPayload): Promise<{ fileId: string; proxyUrl: string }> {
  const folder = resolveMediaFolder(payload.mimeType);
  const fileId = uuidv4();
  const extension = payload.originalName.includes(".")
    ? payload.originalName.split(".").pop()
    : "bin";
  const fileName = `${fileId}-${Date.now()}.${extension}`;
  const objectKey = `${folder}/${fileName}`;

  await uploadObject(objectKey, payload.buffer, payload.mimeType);

  const record: MediaRecord = {
    id: fileId,
    fileName,
    objectKey,
    fileType: folder,
    mimeType: payload.mimeType,
    size: payload.size,
    chatId: payload.chatId,
    senderId: payload.senderId,
    createdAt: new Date(),
  };

  await createMediaRecord(record);

  return {
    fileId,
    proxyUrl: `/file/${fileId}`,
  };
}

export async function resolveSecureFileAccess(fileId: string, userId: string): Promise<string> {
  const media = await getMediaById(fileId);
  if (!media) {
    throw new apiError(404, "File not found");
  }

  const allowed = await isUserInChat(media.chatId, userId);
  if (!allowed) {
    throw new apiError(403, "You are not allowed to access this file");
  }

  return getPresignedGetUrl(media.objectKey);
}

export async function resolveBatchFileAccess(fileIds: string[], userId: string) {
  const mediaRows = await getMediaByIds(fileIds);

  const urls = await Promise.all(
    mediaRows.map(async (media) => {
      const allowed = await isUserInChat(media.chatId, userId);
      if (!allowed) {
        return { fileId: media.id, error: "forbidden" };
      }

      const url = await getPresignedGetUrl(media.objectKey);
      return {
        fileId: media.id,
        proxyUrl: `/file/${media.id}`,
        directUrl: url,
      };
    })
  );

  return urls;
}
