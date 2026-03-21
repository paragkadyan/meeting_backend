import { Request, Response } from "express";
import { apiError } from "../../utils/apiError";
import { asyncHandler } from "../../utils/asyncHandler";
import { resolveBatchFileAccess, resolveSecureFileAccess, uploadMedia } from "../services/media.service";

export const uploadFileController = asyncHandler(async (req: Request, res: Response) => {
  const file = req.file;
  if (!file) {
    throw new apiError(400, "file is required");
  }

  const chatId = String(req.body.chatId || "");
  if (!chatId) {
    throw new apiError(400, "chatId is required");
  }

  if (!req.user?.id) {
    throw new apiError(401, "Unauthorized");
  }

  const result = await uploadMedia({
    originalName: file.originalname,
    mimeType: file.mimetype,
    size: file.size,
    buffer: file.buffer,
    chatId,
    senderId: req.user.id,
  });

  res.status(201).json({
    success: true,
    message: "File uploaded",
    data: result,
  });
});

export const getFileByIdController = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user?.id) {
    throw new apiError(401, "Unauthorized");
  }

  const presignedUrl = await resolveSecureFileAccess(req.params.id, req.user.id);
  res.redirect(302, presignedUrl);
});

export const getBatchFilesController = asyncHandler(async (req: Request, res: Response) => {
  if (!req.user?.id) {
    throw new apiError(401, "Unauthorized");
  }

  const ids = Array.isArray(req.body.fileIds) ? (req.body.fileIds as unknown[]) : [];
  const uniqueIds = [...new Set(ids.map((id: unknown) => String(id)))];

  if (!uniqueIds.length) {
    throw new apiError(400, "fileIds is required");
  }

  const data = await resolveBatchFileAccess(uniqueIds, req.user.id);
  res.status(200).json({ success: true, data });
});

export const mediaHealthController = asyncHandler(async (_req: Request, res: Response) => {
  res.status(200).json({ success: true, message: "media service healthy" });
});
