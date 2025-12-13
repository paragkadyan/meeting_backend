import { redis } from "../db/redis"; // your redis client
import { apiError } from "../utils/apiError";

export const saveTempSignupData = async (email: string, data: any) => {
  try{
  await redis.set(
    `signup:data:${email}`,
    JSON.stringify(data),
    { EX: 10 * 60 }
  ); } catch (error) {
    throw new apiError(500, 'Error saving temporary signup data');
  }
};

export const saveSignupOTP = async (email: string, otp: string) => {
  try{
    await redis.set(
    `signup:otp:${email}`,
    otp,
    { EX: 3 * 60 }
  ); } catch (error) {
    throw new apiError(500, 'Error saving signup OTP');
  }
};

export const getTempSignupData = async (email: string) => {
  try{
  const data = await redis.get(`signup:data:${email}`);
  return data ? JSON.parse(data) : null;
  } catch (error) {
    throw new apiError(500, 'Error retrieving temporary signup data');
  }
}; 

export const getSignupOTP = async (email: string) => {
  try{
  return await redis.get(`signup:otp:${email}`);
  } catch (error) {
    throw new apiError(500, 'Error retrieving signup OTP');
  }
};

export const clearSignupData = async (email: string) => {
  try{
  await redis.del(`signup:data:${email}`);
  await redis.del(`signup:otp:${email}`);
  } catch (error) {
    throw new apiError(500, 'Error clearing signup data');
  }
};
