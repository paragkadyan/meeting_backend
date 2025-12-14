import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import bcrypt from 'bcryptjs';
import { signAccessToken, signRefreshToken, verifyRefreshToken } from '../utils/jwt';
import { registerRefreshToken, revokeRefreshToken, revokeAllOnCompromise } from '../services/token.service';
import { COOKIE_DOMAIN, COOKIE_SECURE, FRONTEND_ORIGIN } from '../config/env';
import { prisma } from '../utils/prismaClient';
import { asyncHandler } from "../utils/asyncHandler";
import { generateOTP, getOTP, genResetToken, getResetToken, clearOTP } from '../services/auth.service';
import { sendTemplatedEmail } from '../services/email.service';
import { clearSignupData, getSignupOTP, getTempSignupData, saveSignupOTP, saveTempSignupData } from '../services/tempUser.service';
import { generateSignature, getCloudinaryConfig } from '../config/cloudinary';
import { apiResponse } from '../utils/apiResponse';
import { apiError } from '../utils/apiError';



export const signup = asyncHandler(async (req: Request, res: Response) => {
  const { name, email, password } = req.body;


  if (!email || !password || !name)
    throw new apiError(400, 'Name, email and password are required.');


  const existingUser = await prisma.user.findUnique({
    where: { email },
  });

  if (existingUser) {
    throw new apiError(409, 'Email already in use.');
  }

  const passwordHash = await bcrypt.hash(password, 10);

  await saveTempSignupData(email, { name, email, passwordHash });
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  await saveSignupOTP(email, otp);

  await sendTemplatedEmail({
    to: email,
    subject: "Your Signup OTP Code",
    templateName: "otp.html",
    variables: {
      otp: otp,
    },
  });

  const response = new apiResponse(200, { user: { email, name } }, 'Signup initiated. OTP sent to email.');

  return res.status(200).json(response);
});

export const resendSignupOTP = asyncHandler(async (req: Request, res: Response) => {
  const { email } = req.body;
  if (!email) throw new apiResponse(400, null, 'Email is required');
  const tempData = await getTempSignupData(email);
  if (!tempData) throw new apiResponse(400, null, 'No signup session found. Please signup again.');
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  await saveSignupOTP(email, otp);

  await sendTemplatedEmail({
    to: email,
    subject: "Your Resent Signup OTP Code",
    templateName: "otp.html",
    variables: {
      otp: otp,
    },
  });
  const response = new apiResponse(200, { user: { email } }, 'OTP resent successfully.');
  return res.status(200).json(response);
});

export const verifySignupOTP = asyncHandler(async (req: Request, res: Response) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    throw new apiError(400, 'Email and OTP are required');
  }

  const savedOtp = await getSignupOTP(email);

  if (!savedOtp || savedOtp !== otp) {
    throw new apiError(400, 'Invalid or expired OTP');
  }

  const tempData = await getTempSignupData(email);

  if (!tempData) {
    throw new apiError(400, 'Session expired. Signup again.');
  }

  const newUser = await prisma.user.create({
    data: {
      name: tempData.name,
      email: tempData.email,
      password: tempData.passwordHash,
    },
  });

  await clearSignupData(email);

  const jti = uuidv4();
  const refreshToken = signRefreshToken({ userId: newUser.id, jti });
  const accessToken = signAccessToken({ userId: newUser.id });

  await sendTemplatedEmail({
    to: email,
    subject: "Welcome to Our App 🎉",
    templateName: "welcome.html",
    variables: {
      name: tempData.name || tempData.email,
      appName: "Heyllow",
      loginUrl: FRONTEND_ORIGIN as string,
    },
  });


  await registerRefreshToken(newUser.id, jti);

  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: 'lax',
    maxAge: 15 * 60 * 1000,
    domain: COOKIE_DOMAIN,
    path: '/',
  });


  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000,
    domain: COOKIE_DOMAIN,
    path: '/',
  });

  const response = new apiResponse(201, { user: { id: newUser.id, email: newUser.email, name: newUser.name } }, 'Signup successful.');
  return res.status(201).json(response);

});;

export const login = asyncHandler(async (req: Request, res: Response) => {

  const { email, password } = req.body;

  if (!email || !password) throw new apiResponse(400, null, 'email and password required');

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) throw new apiError(401, 'invalid credentials');
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) throw new apiError(401, 'invalid credentials');


  const accessToken = signAccessToken({ userId: user.id });
  const jti = uuidv4();
  const refreshToken = signRefreshToken({ userId: user.id, jti });
  await registerRefreshToken(user.id, jti);


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
    path: '/',
  });

  const response = new apiResponse(200, { user: { id: user.id, email: user.email, name: user.name, profilePhoto: user.profileURL, phNumber: user.mobileNumber, dob: user.dob } }, 'login successful');
  return res.status(200).json(response);
});

export const forgotPassword = asyncHandler(async (req: Request, res: Response) => {
  const { email } = req.body;
  if (!email) throw new apiError(400, 'Email is required');


  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) {
    throw new apiError(400, 'If the email is registered, an OTP has been sent.');
  }

  const otp = Math.floor(100000 + Math.random() * 900000).toString();

  await generateOTP(user.id, otp);

  await sendTemplatedEmail({
    to: email,
    subject: "Your Reset OTP Code",
    templateName: "otp.html",
    variables: {
      otp: otp,
    },
  });


  console.log("OTP for password reset:", otp);

  const response = new apiResponse(200, { user: { email: user.email } }, 'OTP has been sent to your email.');

  return res.status(200).json(response);
});

export const verifyResetOtp = asyncHandler(async (req, res) => {
  const { email, otp } = req.body;

  if (!email || !otp) {
    throw new apiError(400, 'Email and OTP are required');
  }

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) throw new apiError(400, 'Invalid request');

  const savedOtp = await getOTP(user.id);

  if (!savedOtp || savedOtp !== otp) {
    throw new apiError(400, 'Invalid or expired OTP');
  }
  await clearOTP(user.id);
  const resetToken = crypto.randomUUID();
  await genResetToken(user.id, resetToken);

  const response = new apiResponse(200, { user: { resetToken } }, 'OTP verified successfully.');

  return res.status(200).json(response)
});

export const resetPassword = asyncHandler(async (req, res) => {
  const { email, newPassword, resetToken } = req.body ?? {};

  if (!email || !newPassword || !resetToken) {
    throw new apiError(400, 'Email, new password and reset token are required');
  }

  const user = await prisma.user.findUnique({ where: { email } });
  if (!user) throw new apiError(400, "Invalid request")

  const savedResetToken = await getResetToken(user.id);

  if (!savedResetToken || savedResetToken !== resetToken) {
    throw new apiError(400, "Invalid or expired reset token")
  }

  const passwordHash = await bcrypt.hash(newPassword, 10);

  await prisma.user.update({
    where: { email },
    data: { password: passwordHash },
  });

  await revokeAllOnCompromise(user.id);

  const response = new apiResponse(200, {}, 'Password reset successful.');

  return res.status(200).json(response);
});

export const logout = asyncHandler(async (req: Request, res: Response) => {
  const token = req.cookies.refreshToken;
  if (token) {
    const payload = verifyRefreshToken(token);
    if (payload.userId && payload.jti) await revokeRefreshToken(payload.userId, payload.jti);
  }


  res.clearCookie('accessToken', { path: '/' });
  res.clearCookie('refreshToken', { path: '/' });

  const response = new apiResponse(200, {}, 'Logout successful.');
  return res.json(response);
});

export const changePassword = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id;
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    throw new apiError(400, 'current password and new password are required');
  }
  const user = await prisma.user.findUnique({ where: { id: userId } });
  if (!user) {
    throw new apiError(404, 'User not found');
  }
  const passwordMatch = await bcrypt.compare(currentPassword, user.password);
  if (!passwordMatch) {
    throw new apiError(401, 'Current password is incorrect');
  }
  const newPasswordMatch = await bcrypt.compare(newPassword, user.password);
  if (newPasswordMatch) {
    throw new apiError(400, 'New password must be different from the current password');
  }
  const newPasswordHash = await bcrypt.hash(newPassword, 10);
  await prisma.user.update({
    where: { id: userId },
    data: { password: newPasswordHash },
  });
  await revokeAllOnCompromise(user.id);
  const response = new apiResponse(200, { user: { id: user.id, email: user.email, name: user.name, profilePhoto: user.profileURL, phNumber: user.mobileNumber, dob: user.dob } }, 'Password changed successfully.');
  return res.status(200).json(response);
});

export const editProfile = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id;
  const { name, location, dob, mobileNumber, profileURL } = req.body;

  const updateData: any = {};

  if (name) {
    updateData.name = name;
  }
  if (location) {
    updateData.location = location;
  }
  if (dob) {
    updateData.dob = dob;
  }
  if (mobileNumber) {
    updateData.mobileNumber = mobileNumber;
  }
  if (profileURL) {
    updateData.profileURL = profileURL;
  }

  if (Object.keys(updateData).length === 0) {
    throw new apiError(400, 'No data provided for update.');
  }

  const user = await prisma.user.update({
    where: { id: userId },
    data: updateData,
  });

  const response = new apiResponse(200, { user: { id: user.id, email: user.email, name: user.name, profilePhoto: user.profileURL, phNumber: user.mobileNumber, dob: user.dob } }, 'Profile edited successfully.');
  return res.status(200).json(response);
});

export const deleteAccount = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id;
  await prisma.user.delete({ where: { id: userId } });
  await revokeAllOnCompromise(userId!);
  res.clearCookie('accessToken', { path: '/' });
  res.clearCookie('refreshToken', { path: '/' });
  const response = new apiResponse(200, {}, 'Account deleted successfully.');
  return res.json(response);
});

export const cloudinarySignature = asyncHandler(async (req: Request, res: Response) => {

  const userId = req.user?.id;
  const timestamp = Math.floor(Date.now() / 1000);
  const folder = 'profile';
  const paramstoSign = { timestamp, folder, public_id: `user_${userId}` };
  const signature = generateSignature(paramstoSign);
  const { cloudName, api_key } = getCloudinaryConfig();
  const response = new apiResponse(200, { user: { id: userId }, cloudinaryData: { cloudName, api_key, timestamp, signature, folder, public_id: `user_${userId}` } }, 'Cloudinary signature generated successfully.');
  return res.json(response)
});

export const getProfile = asyncHandler(async (req: Request, res: Response) => {
  const userId = req.user?.id;
  const user = await prisma.user.findUnique({
    where: { id: userId },
    select: {
      id: true,
      name: true,
      email: true,
      location: true,
      dob: true,
      mobileNumber: true,
      profileURL: true,
    },
  });
  if (!user) {
    throw new apiError(404, 'User not found');
  }
  const response = new apiResponse(200, { user }, 'User profile fetched successfully.');
  return res.status(200).json(response);
});