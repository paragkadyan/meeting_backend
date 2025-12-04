import { redis } from '../db/redis';


const prefix = (userId: string) => `user:${userId}:refresh_tokens`;


export async function registerRefreshToken(userId: string, refreshToken: string) {
    try {
        await redis.sAdd(prefix(userId), refreshToken);
    } catch (error) {
        console.error('Error registering refresh token:', error);
        throw error;
    }
}


export async function revokeRefreshToken(userId: string, refreshToken: string) {
    try {
        await redis.sRem(prefix(userId), refreshToken);
    } catch (error) {
        console.error('Error revoking refresh token:', error);
        throw error;
    }
}


export async function isRefreshTokenActive(userId: string, refreshToken: string) {
    try {
        const res = await redis.sIsMember(prefix(userId), refreshToken);
        return res === 1;
    } catch (error) {
        console.error('Error checking refresh token status:', error);
        throw error;
    }
}

export async function revokeAllUserRefreshTokens(userId: string) {
    try {
        await redis.del(prefix(userId));
    } catch (error) {
        console.error('Error revoking all user refresh tokens:', error);
        throw error;
    }
}
