import { createClient } from "redis";
import {
  REDIS_HOST,
  REDIS_PORT,
} from "../config/env";

export const redis = createClient({
  url: `redis://${REDIS_HOST}:${REDIS_PORT}`
});

export const connectRedis = async () => {
  redis.on("error", (err) => console.error("Redis Error", err));

  await redis.connect();
  console.log("Redis Connected");
};
