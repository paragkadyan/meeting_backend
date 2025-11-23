import app from "./app";
// import { connectPostgres } from "./db/post";
import { connectCassandra } from "./db/cassa";
import { connectRedis } from "./db/redis";

const port = process.env.PORT;
console.log([process.env.DATABASE_URL]);
 (async () => {
//   await connectPostgres();
   await connectCassandra();
   await connectRedis();

 app.listen(port, () => {
     console.log(`Server running on port ${port}`);
 });
 })();


