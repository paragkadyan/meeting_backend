import { bucketName, minioClient } from "../../config/minio";

const PRESIGNED_EXPIRY_SECONDS = Number(process.env.MINIO_PRESIGNED_EXPIRY_SECONDS || 60);

export async function uploadObject(objectKey: string, buffer: Buffer, mimeType: string): Promise<void> {
  await minioClient.putObject(bucketName, objectKey, buffer, buffer.length, {
    "Content-Type": mimeType,
  });
}

export async function getPresignedGetUrl(objectKey: string): Promise<string> {
  return minioClient.presignedGetObject(bucketName, objectKey, PRESIGNED_EXPIRY_SECONDS);
}
