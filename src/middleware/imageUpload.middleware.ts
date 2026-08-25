import multer from "multer";
import { Request, Response, NextFunction } from "express";
import { apiError } from "../utils/apiError";

const MAX_IMAGE_BYTES = Number(process.env.AVATAR_MAX_UPLOAD_BYTES || 5 * 1024 * 1024);
const ALLOWED_IMAGE_MIME_TYPES = new Set(["image/jpeg", "image/png", "image/webp", "image/gif"]);

function formatBytes(bytes: number): string {
  if (bytes >= 1024 * 1024) {
    return `${(bytes / (1024 * 1024)).toFixed(0)}MB`;
  }
  if (bytes >= 1024) {
    return `${(bytes / 1024).toFixed(0)}KB`;
  }
  return `${bytes} bytes`;
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: MAX_IMAGE_BYTES,
  },
  fileFilter: (_req: unknown, file: { mimetype: string }, cb: (error: Error | null, acceptFile?: boolean) => void) => {
    if (!ALLOWED_IMAGE_MIME_TYPES.has(file.mimetype)) {
      cb(new apiError(400, `Image type "${file.mimetype}" is not supported. Allowed types: JPEG, PNG, WebP, GIF`));
      return;
    }
    cb(null, true);
  },
});

// Error handling wrapper for multer
export const imageUploadMiddleware = {
  single: (fieldName: string) => {
    return (req: Request, res: Response, next: NextFunction) => {
      upload.single(fieldName)(req, res, (err: any) => {
        if (err instanceof multer.MulterError) {
          if (err.code === "LIMIT_FILE_SIZE") {
            return next(
              new apiError(
                400,
                `Image size exceeds maximum allowed size of ${formatBytes(MAX_IMAGE_BYTES)}`
              )
            );
          }
          if (err.code === "LIMIT_UNEXPECTED_FILE") {
            return next(new apiError(400, `Unexpected file field: ${err.field}`));
          }
          return next(new apiError(400, `Upload error: ${err.message}`));
        }
        if (err) {
          return next(err);
        }
        next();
      });
    };
  },
};
