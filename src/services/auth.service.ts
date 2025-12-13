import { redis } from '../db/redis';
import { apiError } from '../utils/apiError';


export async function generateOTP(userId: string, otp: string) {
    try {
        await redis.set(`pwd-reset-otp:${userId}`, otp, { EX: 3 * 60 });
    } catch (error) {
       throw new apiError(500,'Error generating OTP');
    }
}

export async function getOTP(userId: string) {
    try {
        const otp = await redis.get(`pwd-reset-otp:${userId}`);
        console.log('Retrieved OTP:', otp);
        return otp;
    } catch (error) {
        throw new apiError(500,'Error retrieving OTP');
    }
}

export async function clearOTP(userId: string) {
    try {
        await redis.del(`pwd-reset-otp:${userId}`);
    } catch (error) {
        throw new apiError(500,'Error clearing OTP');
    }
}

export async function genResetToken(userId: string, resetToken: string) {
    try {
        await redis.set(`pwd-reset-token:${userId}`, resetToken, { EX: 3 * 60 });
    } catch (error) {
        throw new apiError(500,'Error generating reset token');
    }
}

export async function getResetToken(userId: string) {
    try {
        const resetToken = await redis.get(`pwd-reset-token:${userId}`);
        return resetToken;
    } catch (error) {
        throw new apiError(500,'Error retrieving reset token');
    }
}