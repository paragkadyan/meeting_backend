import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '../utils/jwt';
import { registerRefreshToken, revokeRefreshToken, isRefreshTokenActive, revokeAllUserRefreshTokens } from '../services/token.service';
import { COOKIE_DOMAIN, COOKIE_SECURE } from '../config/env';


// Simple in-memory user store (replace with DB service)
const users = new Map<string, { id: string; username: string; passwordHash: string }>();


export async function signup(req: Request, res: Response) {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'username + password required' });
    if (users.has(username)) return res.status(400).json({ error: 'user exists' });


    const id = uuidv4();
    const passwordHash = await bcrypt.hash(password, 10);
    users.set(username, { id, username, passwordHash });
    return res.status(201).json({ id, username });
}

export async function login(req: Request, res: Response) {
    const { username, password } = req.body;
    const user = users.get(username);
    if (!user) return res.status(401).json({ error: 'invalid credentials' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });


    // create tokens
    const accessToken = signAccessToken({ userId: user.id });
    const jti = uuidv4();
    const refreshToken = signRefreshToken({ userId: user.id, jti });
    await registerRefreshToken(user.id, jti);


    // set cookies
    res.cookie('accessToken', accessToken, {
        httpOnly: true,
        secure: COOKIE_SECURE,
        sameSite: 'lax',
        maxAge: 15 * 60 * 1000, // 15 min
        domain: COOKIE_DOMAIN,
        path: '/',
    });


    res.cookie('refreshToken', refreshToken, {
        httpOnly: true,
        secure: COOKIE_SECURE,
        sameSite: 'lax',
        maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
        domain: COOKIE_DOMAIN,
        path: '/auth/refresh',
    });


    return res.json({ ok: true });
}

export async function refresh(req: Request, res: Response) {
    const token = req.cookies.refreshToken;
    if (!token) return res.status(401).json({ error: 'no refresh token' });


    try {
        const payload = verifyRefreshToken(token);
        const userId = payload.userId;
        const jti = payload.jti;
        if (!userId || !jti) return res.status(401).json({ error: 'invalid token payload' });


        if (!await isRefreshTokenActive(userId, jti)) {
            // possible reuse/compromise - revoke all
            // await revokeAllUserRefreshTokens(userId); //issue created for multiple device login
            return res.status(401).json({ error: 'refresh token revoked' });
        }


        // rotate
        await revokeRefreshToken(userId, jti);
        const newJti = uuidv4();
        const newRefreshToken = signRefreshToken({ userId, jti: newJti });
        await registerRefreshToken(userId, newJti);


        const newAccessToken = signAccessToken({ userId });

        // set cookies
        res.cookie('accessToken', newAccessToken, {
            httpOnly: true,
            secure: COOKIE_SECURE,
            sameSite: 'lax',
            maxAge: 15 * 60 * 1000,
            domain: COOKIE_DOMAIN,
            path: '/',
        });


        res.cookie('refreshToken', newRefreshToken, {
            httpOnly: true,
            secure: COOKIE_SECURE,
            sameSite: 'lax',
            maxAge: 7 * 24 * 60 * 60 * 1000,
            domain: COOKIE_DOMAIN,
            path: '/auth/refresh',
        });


        return res.json({ ok: true });
    } catch (err) {
        return res.status(401).json({ error: 'invalid refresh token' });
    }
}

export async function logout(req: Request, res: Response) {
    const token = req.cookies.refreshToken;
    if (token) {
        try {
            const payload = verifyRefreshToken(token);
            if (payload.userId && payload.jti) await revokeRefreshToken(payload.userId, payload.jti);
        } catch (e) {
            // ignore
        }
    }


    res.clearCookie('accessToken', { path: '/' });
    res.clearCookie('refreshToken', { path: '/auth/refresh' });
    return res.json({ ok: true });
}