import { Router } from "express";
import {
  deleteFileByIdController,
  getBatchFilesController,
  getBatchGroupAvatarsController,
  getBatchProfilePicturesController,
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
mediaRouter.post("/profile-pictures/batch", mediaAuthMiddleware, getBatchProfilePicturesController);
mediaRouter.post("/group-avatars/batch", mediaAuthMiddleware, getBatchGroupAvatarsController);
mediaRouter.get("/file/:id", mediaAuthMiddleware, getFileByIdController);
mediaRouter.delete("/file/:id", mediaAuthMiddleware, deleteFileByIdController);
mediaRouter.post("/files/batch", mediaAuthMiddleware, getBatchFilesController);

export default mediaRouter;
