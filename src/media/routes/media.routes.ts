import { Router } from "express";
import {
  deleteFileByIdController,
  getBatchFilesController,
  getFileByIdController,
  mediaHealthController,
  uploadFileController,
} from "../controllers/media.controller";
import { mediaAuthMiddleware } from "../middleware/mediaAuth.middleware";
import { uploadMiddleware } from "../middleware/upload.middleware";
import { uploadRateLimiter } from "../middleware/uploadRateLimiter.middleware";

const mediaRouter = Router();

mediaRouter.get("/api/health", mediaHealthController);
mediaRouter.post("/api/upload", mediaAuthMiddleware, uploadRateLimiter, uploadMiddleware.single("file"), uploadFileController);
mediaRouter.get("/api/file/:id", mediaAuthMiddleware, getFileByIdController);
mediaRouter.delete("/api/file/:id", mediaAuthMiddleware, deleteFileByIdController);
mediaRouter.post("/api/files/batch", mediaAuthMiddleware, getBatchFilesController);

export default mediaRouter;
