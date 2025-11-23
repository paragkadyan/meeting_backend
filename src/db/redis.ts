import { createClient } from "redis";

export const redis = createClient({
    url: `redis://${process.env.REDIS_HOST}:${process.env.REDIS_PORT}`
});

export const connectRedis = async () => {
  redis.on("error", (err) => console.error("Redis Error", err));

  await redis.connect();
  console.log("Redis Connected");
};
