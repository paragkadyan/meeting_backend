import { redis } from '../db/redis';


const prefix = (userId: string) => `user:${userId}:refresh_tokens`;


export async function registerRefreshToken(userId: string, jti: string) {
    await redis.sAdd(prefix(userId), jti);
}


export async function revokeRefreshToken(userId: string, jti: string) {
    await redis.sRem(prefix(userId), jti);
}


export async function isRefreshTokenActive(userId: string, jti: string) {
    const res = await redis.sIsMember(prefix(userId), jti);
    return res === 1;
}


export async function revokeAllUserRefreshTokens(userId: string) {
    await redis.del(prefix(userId));
}