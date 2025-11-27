import app from "./app";
import { connectPostgres } from "./db/post";
import { connectCassandra } from "./db/cassa";
import { connectRedis } from "./db/redis";
import { PORT } from './config/env';

(async () => {
  await connectPostgres();
  await connectCassandra();
  await connectRedis();

  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
})();


