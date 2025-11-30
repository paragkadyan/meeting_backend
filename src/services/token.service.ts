import { refresh } from '../controllers/auth.controller';
import { redis } from '../db/redis';


const prefix = (userId: string) => `user:${userId}:refresh_tokens`;


export async function registerRefreshToken(userId: string, refreshToken: string) {
    await redis.sAdd(prefix(userId), refreshToken);
}


export async function revokeRefreshToken(userId: string, refreshToken: string) {
    await redis.sRem(prefix(userId), refreshToken);
}


export async function isRefreshTokenActive(userId: string, refreshToken: string) {
    const res = await redis.sIsMember(prefix(userId), refreshToken);
    return res === 1;
}


export async function revokeAllUserRefreshTokens(userId: string) {
    await redis.del(prefix(userId));
}