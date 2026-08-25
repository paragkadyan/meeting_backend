import multer from "multer";
import { Request, Response, NextFunction } from "express";
import { apiError } from "../../utils/apiError";
import { MAX_UPLOAD_BYTES, validateMimeType } from "../utils/fileType";

const storage = multer.memoryStorage();

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
  storage,
  limits: {
    fileSize: MAX_UPLOAD_BYTES,
  },
  fileFilter: (
    _req: unknown,
    file: { mimetype: string },
    cb: (error: Error | null, acceptFile?: boolean) => void
  ) => {
    if (!validateMimeType(file.mimetype)) {
      cb(new apiError(400, `File type "${file.mimetype}" is not supported`));
      return;
    }
    cb(null, true);
  },
});

// Error handling wrapper for multer
export const uploadMiddleware = {
  single: (fieldName: string) => {
    return (req: Request, res: Response, next: NextFunction) => {
      upload.single(fieldName)(req, res, (err: any) => {
        if (err instanceof multer.MulterError) {
          if (err.code === "LIMIT_FILE_SIZE") {
            return next(
              new apiError(
                400,
                `File size exceeds maximum allowed size of ${formatBytes(MAX_UPLOAD_BYTES)}`
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
