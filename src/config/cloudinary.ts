import { v2 as cloudinary } from 'cloudinary';
import dotenv from 'dotenv';
import { CLOUDINARY_API_KEY, CLOUDINARY_API_SECRET, CLOUDINARY_CLOUD_NAME } from './env';
import { apiError } from '../utils/apiError';

dotenv.config();

cloudinary.config({
  cloud_name: CLOUDINARY_CLOUD_NAME,
  api_key:    CLOUDINARY_API_KEY,
  api_secret: CLOUDINARY_API_SECRET,
});

export function generateSignature(params: Record<string, string | number>) {
  try{
  return cloudinary.utils.api_sign_request(
    params,
    CLOUDINARY_API_SECRET!
  );} catch (error) {
    throw new apiError(500, 'Cloudinary signature generation failed');
  }
}

export function getCloudinaryConfig() {
  return {
    cloudName: CLOUDINARY_CLOUD_NAME!,
    api_key: CLOUDINARY_API_KEY!,
  };
}

export {cloudinary};
