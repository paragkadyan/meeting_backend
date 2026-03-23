export type MediaType = "images" | "audio" | "video" | "docs";

const ALLOWED_MIME_PREFIXES = ["image/", "audio/", "video/"];
const ALLOWED_DOC_MIME_TYPES = new Set([
  "application/pdf",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "application/vnd.ms-excel",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  "text/plain",
]);

export const MAX_UPLOAD_BYTES = Number(process.env.MEDIA_MAX_UPLOAD_BYTES || 25 * 1024 * 1024);
const DEFAULT_UPLOAD_LIMITS: Record<MediaType, number> = {
  images: Number(process.env.MEDIA_IMAGE_MAX_UPLOAD_BYTES || 10 * 1024 * 1024),
  audio: Number(process.env.MEDIA_AUDIO_MAX_UPLOAD_BYTES || 20 * 1024 * 1024),
  video: Number(process.env.MEDIA_VIDEO_MAX_UPLOAD_BYTES || 100 * 1024 * 1024),
  docs: Number(process.env.MEDIA_DOC_MAX_UPLOAD_BYTES || 25 * 1024 * 1024),
};

export function resolveMediaFolder(mimeType: string): MediaType {
  if (mimeType.startsWith("image/")) return "images";
  if (mimeType.startsWith("audio/")) return "audio";
  if (mimeType.startsWith("video/")) return "video";
  if (ALLOWED_DOC_MIME_TYPES.has(mimeType)) return "docs";

  throw new Error("Unsupported file MIME type");
}

export function validateMimeType(mimeType: string): boolean {
  return (
    ALLOWED_MIME_PREFIXES.some((prefix) => mimeType.startsWith(prefix)) ||
    ALLOWED_DOC_MIME_TYPES.has(mimeType)
  );
}

export function getUploadLimitBytes(mimeType: string): number {
  const mediaType = resolveMediaFolder(mimeType);
  return DEFAULT_UPLOAD_LIMITS[mediaType];
}

export function validateUploadSize(mimeType: string, size: number): void {
  const mediaType = resolveMediaFolder(mimeType);
  const maxSize = DEFAULT_UPLOAD_LIMITS[mediaType];
  if (size > maxSize) {
    throw new Error(`${mediaType} upload exceeds max allowed size of ${maxSize} bytes`);
  }
}
