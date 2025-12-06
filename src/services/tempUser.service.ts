import { redis } from "../db/redis"; // your redis client

export const saveTempSignupData = async (email: string, data: any) => {
  await redis.set(
    `signup:data:${email}`,
    JSON.stringify(data),
    {EX: 10 * 60 }
  );
};

export const saveSignupOTP = async (email: string, otp: string) => {
  await redis.set(
    `signup:otp:${email}`,
    otp,
    {EX: 2 * 60 }
  );
};

export const getTempSignupData = async (email: string) => {
  const data = await redis.get(`signup:data:${email}`);
  return data ? JSON.parse(data) : null;
};

export const getSignupOTP = async (email: string) => {
  return await redis.get(`signup:otp:${email}`);
};

export const clearSignupData  = async (email: string) => {
  await redis.del(`signup:data:${email}`);
   await redis.del(`signup:otp:${email}`);
};
