import app from "./app";
import { connectPostgres } from "./db/post";
import { connectCassandra } from "./db/cassa";
import { connectRedis } from "./db/redis";
import { PORT } from './config/env';
import { apiError } from "./utils/apiError";
import http from "http";
import { initSocket } from "./socket";

(async () => {
  try{
  await connectPostgres();
  await connectCassandra();
  await connectRedis();
  } catch (error) {
    throw new apiError(500, 'Database connection failed', [error as Error]);
  }

const server = http.createServer(app);

initSocket(server); 

server.listen(PORT, () => { console.log(`Server running on http://localhost:${PORT}`); });
})();


