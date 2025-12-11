import { Request, Response, NextFunction } from 'express';
import { verifyAccessToken, verifyRefreshToken, signAccessToken, signRefreshToken } from '../utils/jwt';
import { isRefreshTokenActive, revokeRefreshToken, registerRefreshToken } from '../services/token.service';
import { COOKIE_SECURE, COOKIE_DOMAIN } from '../config/env';
import { v4 as uuidv4 } from 'uuid';


export async function authMiddleware(req: Request, res: Response, next: NextFunction) {
    const access = req.cookies.accessToken;
    const refresh = req.cookies.refreshToken;
    
    if (!access && !refresh) return res.status(401).json({ error: 'refresh 1 unauthorized' });


    try {
        const payload = verifyAccessToken(access);
        req.user = { id: payload.userId };
        return next();
    } catch (err) {
        if (!refresh) return res.status(401).json({ error: ' refresh unauthorized' });


        try {
            const payload = verifyRefreshToken(refresh);
            const userId = payload.userId;
            const jti = payload.jti;
            if (!await isRefreshTokenActive(userId, jti)) {
                await revokeAllOnCompromise(userId);
                return res.status(401).json({ error: 'refresh revoked' });
            }

            await revokeRefreshToken(userId, jti);
            const newJti = uuidv4();
            const newRefresh = signRefreshToken({ userId, jti: newJti });
            await registerRefreshToken(userId, newJti);


            const newAccess = signAccessToken({ userId });


            res.cookie('accessToken', newAccess, {
                httpOnly: true,
                secure: COOKIE_SECURE,
                sameSite: 'lax',
                maxAge: 15 * 60 * 1000,
                domain: COOKIE_DOMAIN,
                path: '/',
            });
            res.cookie('refreshToken', newRefresh, {
                httpOnly: true,
                secure: COOKIE_SECURE,
                sameSite: 'lax',
                maxAge: 7 * 24 * 60 * 60 * 1000,
                domain: COOKIE_DOMAIN,
                path: '/auth/refresh',
            });


            req.user = { id: userId };
            return next();
        } catch (e) {
            return res.status(401).json({ error: 'invalid refresh token' });
        }
    }
}


async function revokeAllOnCompromise(userId: string) {
    // Implement additional handling (notify user, revoke sessions)
    // For now, revoke all refresh tokens:
    await (await import('../services/token.service')).revokeAllUserRefreshTokens(userId);
}