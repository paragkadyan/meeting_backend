export class apiError extends Error {
  statusCode: number;
  success: boolean;
  errors: any[];
  data: unknown;

  constructor(
    statusCode: number,
    message: string = "Something went wrong",
    errors: any[] = [],
    data: unknown = null
  ) {
    super(message);
    this.statusCode = statusCode;
    this.success = false;
    this.errors = errors;
    this.data = data;

    Error.captureStackTrace(this, this.constructor);
  }
}
