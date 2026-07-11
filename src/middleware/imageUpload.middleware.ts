import multer from "multer";
import { apiError } from "../utils/apiError";

const MAX_IMAGE_BYTES = Number(process.env.AVATAR_MAX_UPLOAD_BYTES || 5 * 1024 * 1024);
const ALLOWED_IMAGE_MIME_TYPES = new Set(["image/jpeg", "image/png", "image/webp", "image/gif"]);

export const imageUploadMiddleware = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_IMAGE_BYTES,
  },
  fileFilter: (_req: unknown, file: { mimetype: string }, cb: (error: Error | null, acceptFile?: boolean) => void) => {
    if (!ALLOWED_IMAGE_MIME_TYPES.has(file.mimetype)) {
      cb(new apiError(400, "Unsupported image MIME type"));
      return;
    }
    cb(null, true);
  },
});
