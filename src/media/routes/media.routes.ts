import { Router } from "express";
import {
  getBatchFilesController,
  getFileByIdController,
  mediaHealthController,
  uploadFileController,
} from "../controllers/media.controller";
import { mediaAuthMiddleware } from "../middleware/mediaAuth.middleware";
import { uploadMiddleware } from "../middleware/upload.middleware";
import { uploadRateLimiter } from "../middleware/uploadRateLimiter.middleware";

const mediaRouter = Router();

mediaRouter.get("/health", mediaHealthController);
mediaRouter.post("/upload", mediaAuthMiddleware, uploadRateLimiter, uploadMiddleware.single("file"), uploadFileController);
mediaRouter.get("/file/:id", mediaAuthMiddleware, getFileByIdController);
mediaRouter.post("/files/batch", mediaAuthMiddleware, getBatchFilesController);

export default mediaRouter;
