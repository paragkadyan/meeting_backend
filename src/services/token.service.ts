import { redis } from '../db/redis';
import { apiError } from '../utils/apiError';

const REFRESH_TTL = 7 * 24 * 60 * 60;

export async function registerRefreshToken(userId: string, jti: string) {
    try {
        await redis.set(`refresh:${userId}:${jti}`, "active", { EX: REFRESH_TTL });
    } catch (error) {
      throw new apiError(500, 'Error registering refresh token');
    }
}


export async function revokeRefreshToken(userId: string, jti: string) {
    try {
       await redis.del(`refresh:${userId}:${jti}`);
    } catch (error) {
        throw new apiError(500, 'Error revoking refresh token');
    }
}


export async function isRefreshTokenActive(userId: string, jti: string) {
    try {
        const val = await redis.get(`refresh:${userId}:${jti}`);
        return val === "active";
    } catch (error) {
        throw new apiError(500, 'Error checking refresh token status');
    }
}

export async function revokeAllOnCompromise(userId: string) {
    try {
        const keys = await redis.keys(`refresh:${userId}:*`);
        if (keys.length) await redis.del(keys);
    } catch (error) {
        throw new apiError(500, 'Error revoking all refresh tokens on compromise');
    }
}
