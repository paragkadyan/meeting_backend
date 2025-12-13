import { Request, Response, NextFunction } from "express";
import { apiError } from "../utils/apiError";

export const errorHandler = (
  err: any,
  _req: Request,
  res: Response,
  _next: NextFunction
) => {
  //console.error("Error:", err);

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
    message: "Internal Server Error",
  });
};
