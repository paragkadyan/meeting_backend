import app from "./app";
import { connectPostgres } from "./db/post";
import { connectCassandra } from "./db/cassa";
import { connectRedis } from "./db/redis";
import { PORT } from './config/env';
import { apiError } from "./utils/apiError";
import http from "http";
import { initSocket } from "./socket";
import { ensureMediaBucket } from "./config/minio";
import { initMediaTable } from "./media/repositories/media.repository";
import { logger } from "./logger/logger";

(async () => {
  try{
  await connectPostgres();
  await connectCassandra();
  await connectRedis();
  await ensureMediaBucket();
  await initMediaTable();
  } catch (error) {
    throw new apiError(500, 'Database connection failed', [error as Error]);
  }

const server = http.createServer(app);

initSocket(server);

server.listen(PORT, () => { logger.info(`Server running on http://localhost:${PORT}`); });
})();

