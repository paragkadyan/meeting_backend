import { bucketName, minioClient } from "../../config/minio";

const PRESIGNED_EXPIRY_SECONDS = Number(process.env.MINIO_PRESIGNED_EXPIRY_SECONDS || 60);

export async function uploadObject(objectKey: string, buffer: Buffer, mimeType: string): Promise<void> {
  await minioClient.putObject(bucketName, objectKey, buffer, buffer.length, {
    "Content-Type": mimeType,
  });
}

function buildContentDispositionFileName(fileName: string): string {
  const sanitized = fileName.replace(/[\r\n"]/g, "_");
  return `inline; filename="${sanitized}"; filename*=UTF-8''${encodeURIComponent(sanitized)}`;
}

export async function getPresignedGetUrl(objectKey: string, fileName?: string): Promise<string> {
  const reqParams = fileName
    ? {
        "response-content-disposition": buildContentDispositionFileName(fileName),
      }
    : undefined;

  return minioClient.presignedGetObject(bucketName, objectKey, PRESIGNED_EXPIRY_SECONDS, reqParams);
}

export async function deleteObject(objectKey: string): Promise<void> {
  await minioClient.removeObject(bucketName, objectKey);
}
