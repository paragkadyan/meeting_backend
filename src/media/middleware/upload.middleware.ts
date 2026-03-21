import multer from "multer";
import { apiError } from "../../utils/apiError";
import { MAX_UPLOAD_BYTES, validateMimeType } from "../utils/fileType";

const storage = multer.memoryStorage();

export const uploadMiddleware = multer({
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
      cb(new apiError(400, "Unsupported MIME type"));
      return;
    }
    cb(null, true);
  },
});
