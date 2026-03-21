import { Client } from "minio";

const endpoint = process.env.MINIO_ENDPOINT || "localhost";
const port = Number(process.env.MINIO_PORT || 9000);
const useSSL = process.env.MINIO_USE_SSL === "true";
const accessKey = process.env.MINIO_ACCESS_KEY || "";
const secretKey = process.env.MINIO_SECRET_KEY || "";
export const bucketName = process.env.MINIO_BUCKET_NAME || "chat-media";

export const minioClient = new Client({
  endPoint: endpoint,
  port,
  useSSL,
  accessKey,
  secretKey,
});

export async function ensureMediaBucket(): Promise<void> {
  const exists = await minioClient.bucketExists(bucketName);
  if (!exists) {
    await minioClient.makeBucket(bucketName, "us-east-1");
  }
}
