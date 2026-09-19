import { redis } from '../db/redis';
import { apiError } from '../utils/apiError';
import { getTokenMaxAge } from '../utils/jwt';

export async function registerRefreshToken(userId: string, jti: string, refreshToken: string) {
    try {
        const refreshTtl = Math.max(1, Math.ceil(getTokenMaxAge(refreshToken) / 1000));
        await redis.set(`refresh:${userId}:${jti}`, "active", { EX: refreshTtl });
    } catch (error) {
      throw new apiError(500, 'Error registering refresh token');
    }
}

/**
 * Consume the old refresh JTI and activate the replacement as one Redis
 * operation.  This prevents two concurrent requests from both treating the
 * same refresh token as active during rotation.
 */
export async function rotateRefreshToken(
    userId: string,
    oldJti: string,
    newJti: string,
    newRefreshToken: string
) {
    try {
        const refreshTtl = Math.max(1, Math.ceil(getTokenMaxAge(newRefreshToken) / 1000));
        const oldKey = `refresh:${userId}:${oldJti}`;
        const newKey = `refresh:${userId}:${newJti}`;
        const result = await redis.eval(
            `if redis.call('GET', KEYS[1]) ~= 'active' then return 0 end
             redis.call('DEL', KEYS[1])
             redis.call('SET', KEYS[2], 'active', 'EX', ARGV[1])
             return 1`,
            { keys: [oldKey, newKey], arguments: [String(refreshTtl)] }
        );
        return result === 1;
    } catch (error) {
        throw new apiError(500, 'Error rotating refresh token');
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
