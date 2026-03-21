import { Request, Response, NextFunction } from "express";
import { apiError } from "../utils/apiError";
import { logger } from "../logger/logger";

export const errorHandler = (
  err: any,
  _req: Request,
  res: Response,
  _next: NextFunction
) => {
  logger.error("Unhandled error", { message: err?.message, stack: err?.stack });

  if (err instanceof apiError) {
    return res.status(err.statusCode).json({
      success: err.success,
      message: err.message,
      errors: err.errors,
      data: err.data,
    });
  }

  res.status(500).json({
    success: false,
    error: err.message,
    message: "Internal Server Error",
  });
};
