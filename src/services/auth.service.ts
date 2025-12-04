import { redis } from '../db/redis';


export async function generateOTP(userId: string, otp: string) {
    try {
        await redis.set(`pwd-reset-otp:${userId}`, otp, { EX: 3 * 60 });
    } catch (error) {
        console.error('Error registering refresh token:', error);
        throw error;
    }
}

export async function getOTP(userId: string) {
    try {
        const otp = await redis.get(`pwd-reset-otp:${userId}`);
        console.log('Retrieved OTP:', otp);
        return otp;
    } catch (error) {
        console.error('Error retrieving OTP:', error);
        throw error;
    }
}

export async function clearOTP(userId: string) {
    try {
        await redis.del(`pwd-reset-otp:${userId}`);
    } catch (error) {
        throw error;
    }
}

export async function genResetToken(userId: string, resetToken: string) {
    try {
        await redis.set(`pwd-reset-token:${userId}`, resetToken, { EX: 3 * 60 });
    } catch (error) {
        console.error('Error generating reset token:', error);
        throw error;
    }
}

export async function getResetToken(userId: string) {
    try {
        const resetToken = await redis.get(`pwd-reset-token:${userId}`);
        return resetToken;
    } catch (error) {
        console.error('Error retrieving reset token:', error);
        throw error;
    }
}