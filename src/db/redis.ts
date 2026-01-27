import { createClient } from "redis";
import { REDIS_HOST, REDIS_PORT } from "../config/env";

export const redis = createClient({
  url: `redis://${REDIS_HOST}:${REDIS_PORT}`,
});

let isConnected = false;

export const connectRedis = async () => {
  if (isConnected) return;

  redis.on("error", (err) =>
    console.error("Redis Error", err)
  );

  await redis.connect();
  isConnected = true;

  console.log("Redis Connected");
};
