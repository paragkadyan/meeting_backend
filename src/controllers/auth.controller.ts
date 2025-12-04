import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '../utils/jwt';
import { registerRefreshToken, revokeRefreshToken, isRefreshTokenActive, revokeAllUserRefreshTokens } from '../services/token.service';
import { COOKIE_DOMAIN, COOKIE_SECURE } from '../config/env';
import { prisma } from '../utils/prismaClient';
import { asyncHandler } from "../utils/asyncHandler";
import { generateOTP, getOTP, genResetToken, getResetToken } from '../services/auth.service';
import { sendTemplatedEmail } from '../services/email.service';



export const signup = asyncHandler(async (req: Request, res: Response) => {
  const { email, password } = req.body;
  console.log(email, password);

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

  // send email
  await sendTemplatedEmail({
    to: email,
    subject: "Welcome to Our App 🎉",
    templateName: "welcome.html",
    variables: {
      name: "Pika",
      appName: "Chat App",
      loginUrl: "https://app.dotlinker.com/login",
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

})

export const login = asyncHandler(async (req: Request, res: Response) => {

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
})

export const forgotPassword = asyncHandler(async (req: Request, res: Response) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'email required' });


  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    return res.status(409).json({
      message: "Email doesn't exists.",
    });
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  await generateOTP(user.id, otp);

  //waiting for smtp setup
  await sendTemplatedEmail({
    to: email,
    subject: "Your OTP Code",
    templateName: "otp.html",
    variables: {
      otp: otp,
    },
  });


  console.log("OTP for password reset:", otp);

  return res.status(200).json({
    email: user.email,
    message: "OTP has been sent to your email.",
  });
})

export const verifyResetOtp = asyncHandler(async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    return res.status(400).json({ error: "Email + OTP required" });
  }

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(400).json({ error: "Invalid OTP" });

  const savedOtp = await getOTP(user.id);

  if (!savedOtp || savedOtp !== otp) {
    return res.status(400).json({ error: "Invalid or expired OTP" });
  }

  const resetToken = crypto.randomUUID();
  await genResetToken(user.id, resetToken);

  return res.status(200).json({
    resetToken,
    message: "OTP verified successfully",
  })
})

export const resetPassword = asyncHandler(async (req, res) => {
  const { email, newPassword, resetToken } = req.body ?? {};

  if (!email || !newPassword || !resetToken) {
    return res.status(400).json({ error: "Email + new password required" });
  }

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) return res.status(400).json({ error: "Invalid request" });

  const savedResetToken = await getResetToken(user.id);

  if (!savedResetToken || savedResetToken !== resetToken) {
    return res.status(400).json({ error: "Invalid or expired reset token" });
  }

  const passwordHash = await bcrypt.hash(newPassword, 10);

  await prisma.user.update({
    where: { email },
    data: { password: passwordHash },
  });

  await generateOTP(user.id, '');

  return res.status(200).json({ message: "Password reset successful" });
})


export const refresh = asyncHandler(async (req: Request, res: Response) => {
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
})

export const logout = asyncHandler(async (req: Request, res: Response) => {
  const token = req.cookies.refreshToken;
  if (token) {
    try {
      const payload = verifyRefreshToken(token);
      if (payload.userId && payload.jti) await revokeRefreshToken(payload.userId, payload.jti);
    } catch (e) {
      console.error('Error during logout token verification:', e);
    }
  }


  res.clearCookie('accessToken', { path: '/' });
  res.clearCookie('refreshToken', { path: '/auth/refresh' });
  return res.json({ ok: true });
})

