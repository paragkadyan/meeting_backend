import path from "path";
import { minioClient, bucketName } from "../config/minio";

const PROFILE_PREFIX = "profile-pictures";
const GROUP_AVATAR_PREFIX = "group-avatars";
export interface UploadedImageFile {
  originalname: string;
  mimetype: string;
  size: number;
  buffer: Buffer;
}

const ALLOWED_IMAGE_MIME_TYPES = new Set(["image/jpeg", "image/png", "image/webp", "image/gif"]);

function extensionForMimeType(mimeType: string, originalName: string): string {
  const originalExtension = path.extname(originalName).toLowerCase().replace(".", "");
  if (["jpg", "jpeg", "png", "webp", "gif"].includes(originalExtension)) {
    return originalExtension === "jpeg" ? "jpg" : originalExtension;
  }

  switch (mimeType) {
    case "image/jpeg":
      return "jpg";
    case "image/png":
      return "png";
    case "image/webp":
      return "webp";
    case "image/gif":
      return "gif";
    default:
      return "bin";
  }
}

function isManagedAssetKey(value: string | null | undefined, prefix: string): value is string {
  return typeof value === "string" && value.startsWith(`${prefix}/`);
}

async function uploadManagedImage(params: {
  prefix: string;
  id: string;
  file: UploadedImageFile;
}): Promise<string> {
  const { file, id, prefix } = params;

  if (!ALLOWED_IMAGE_MIME_TYPES.has(file.mimetype)) {
    throw new Error("Unsupported image MIME type");
  }

  const extension = extensionForMimeType(file.mimetype, file.originalname);
  const objectKey = `${prefix}/${id}.${extension}`;

  await minioClient.putObject(bucketName, objectKey, file.buffer, file.size, {
    "Content-Type": file.mimetype,
  });

  return objectKey;
}

async function replaceManagedImage(params: {
  prefix: string;
  id: string;
  file: UploadedImageFile;
  previousObjectKey?: string | null;
}): Promise<string> {
  const { previousObjectKey, prefix } = params;
  const newObjectKey = await uploadManagedImage(params);

  if (isManagedAssetKey(previousObjectKey, prefix) && previousObjectKey !== newObjectKey) {
    await minioClient.removeObject(bucketName, previousObjectKey);
  }

  return newObjectKey;
}

export async function replaceProfilePicture(
  userId: string,
  file: UploadedImageFile,
  previousObjectKey?: string | null
): Promise<string> {
  return replaceManagedImage({
    prefix: PROFILE_PREFIX,
    id: userId,
    file,
    previousObjectKey,
  });
}

export async function replaceGroupAvatar(
  conversationId: string,
  file: UploadedImageFile,
  previousObjectKey?: string | null
): Promise<string> {
  return replaceManagedImage({
    prefix: GROUP_AVATAR_PREFIX,
    id: conversationId,
    file,
    previousObjectKey,
  });
}

export async function deleteProfilePicture(objectKey?: string | null): Promise<void> {
  if (isManagedAssetKey(objectKey, PROFILE_PREFIX)) {
    await minioClient.removeObject(bucketName, objectKey);
  }
}

export async function deleteGroupAvatar(objectKey?: string | null): Promise<void> {
  if (isManagedAssetKey(objectKey, GROUP_AVATAR_PREFIX)) {
    await minioClient.removeObject(bucketName, objectKey);
  }
}
