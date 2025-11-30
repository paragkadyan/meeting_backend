import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '../utils/jwt';
import { registerRefreshToken, revokeRefreshToken, isRefreshTokenActive, revokeAllUserRefreshTokens } from '../services/token.service';
import { COOKIE_DOMAIN, COOKIE_SECURE } from '../config/env';
import { prisma } from '../utils/prismaClient';
import { ref } from 'process';



export async function signup(req: Request, res: Response) {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ error: 'email + password required' });

    const existingUser = await prisma.user.findUnique({
      where: { email },
    });

    if (existingUser) {
      return res.status(409).json({ error: 'Email already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const newUser = await prisma.user.create({
      data: {
        email,
        password: passwordHash,
      },
    });

    const jti = uuidv4();
    const refreshToken = signRefreshToken({ userId: newUser.id, jti });
    const accessToken = signAccessToken({ userId: newUser.id });


    await registerRefreshToken(newUser.id, refreshToken);

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


    return res.status(201).json({
      id: newUser.id,
      email: newUser.email,
    });

  } catch (err) {
    console.error("Signup error:", err);
    return res.status(500).json({ error: 'Internal Server Error' });
  }
}

export async function login(req: Request, res: Response) {

    const { email, password } = req.body;

    if (!email || !password) return res.status(400).json({ error: 'email + password required' });

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(401).json({ error: 'invalid credentials' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });


    // create tokens
    const accessToken = signAccessToken({ userId: user.id });
    const jti = uuidv4();
    const refreshToken = signRefreshToken({ userId: user.id, jti });
    await registerRefreshToken(user.id, refreshToken);


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


    return res.status(200).json({
      id: user.id,
      email: user.email,
      message: 'login successful',
    });
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