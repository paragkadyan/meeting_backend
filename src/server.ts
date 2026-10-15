import app from "./app";
import { connectPostgres } from "./db/post";
import { connectCassandra } from "./db/cassa";
import { connectRedis } from "./db/redis";
import { PORT } from './config/env';
import { apiError } from "./utils/apiError";
import http from "http";
import { initSocket } from "./socket";
import { ensureMediaBucket } from "./config/minio";
import { logger } from "./logger/logger";
import { startCallTimeoutWorker } from "./services/call.service";

(async () => {
  let step = "PostgreSQL";

  try {
    await connectPostgres();

    step = "Cassandra";
    await connectCassandra();

    step = "Redis";
    await connectRedis();

    step = "MinIO bucket initialization";
    await ensureMediaBucket();
  } catch (error) {
    logger.error(`Startup failed at ${step}`, {
      error: error instanceof Error
        ? error.message
        : String(error),
      stack: error instanceof Error
        ? error.stack
        : undefined,
    });

    throw new apiError(500, "Database connection failed", [
      error instanceof Error ? error : new Error(String(error)),
    ]);
  }

  const server = http.createServer(app);

  initSocket(server);
  startCallTimeoutWorker();

  server.listen(PORT, () => {
    logger.info(`Server running on http://localhost:${PORT}`);
  });
})();