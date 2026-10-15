import { Client } from "minio";

const endpoint = process.env.MINIO_ENDPOINT || "localhost";
const port = Number(process.env.MINIO_PORT || 9000);
const useSSL = process.env.MINIO_USE_SSL === "true";
const accessKey = process.env.MINIO_ACCESS_KEY || "";
const secretKey = process.env.MINIO_SECRET_KEY || "";
export const bucketName = process.env.MINIO_BUCKET_NAME || "chat-media";
// Bucket is created in this region (ensureMediaBucket); setting it on the
// clients also stops presigning from making a region-lookup network call.
const region = process.env.MINIO_REGION || "us-east-1";

/** Used by the server itself for uploads, deletes and bucket setup. */
export const minioClient = new Client({
  endPoint: endpoint,
  port,
  useSSL,
  accessKey,
  secretKey,
  region,
});

/**
 * Signs the download links handed to clients. Presigned URLs embed the host
 * they were signed for, and clients fetch them directly, so this must be an
 * address *clients* can reach. With MINIO_ENDPOINT=localhost the web app on
 * the same PC works, but phones can't (localhost is the phone itself). Set
 * MINIO_PUBLIC_ENDPOINT to the LAN IP in development, or the public media
 * host in production. Defaults to the internal endpoint.
 */
export const presignClient = process.env.MINIO_PUBLIC_ENDPOINT
  ? new Client({
      endPoint: process.env.MINIO_PUBLIC_ENDPOINT,
      port: Number(process.env.MINIO_PUBLIC_PORT || port),
      useSSL: process.env.MINIO_PUBLIC_USE_SSL ? process.env.MINIO_PUBLIC_USE_SSL === "true" : useSSL,
      accessKey,
      secretKey,
      region,
    })
  : minioClient;

export async function ensureMediaBucket(): Promise<void> {
  const exists = await minioClient.bucketExists(bucketName);
  if (!exists) {
    await minioClient.makeBucket(bucketName, region);
  }
}
