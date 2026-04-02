import { cassandra } from "../db/cassa";
import { asyncHandler } from "../utils/asyncHandler";
import { apiResponse } from "../utils/apiResponse";
import { apiError } from "../utils/apiError";
import { redis } from "../db/redis";
import { prisma } from '../db/post';
import bcrypt from "bcryptjs/umd/types";
import { COOKIE_SECURE } from "../config/env";
import { registerRefreshToken } from "../services/token.service";
import { signAccessToken, signRefreshToken } from "../utils/jwt";
import { v4 as uuidv4 } from 'uuid';

export const getAllUsers = asyncHandler(async (req, res) => {
    const users = await prisma.user.findMany({
        select: {
            id: true,
            name: true,
            email: true,
            lname: true,
            mobileNumber: true,
        },
    });
    return res.status(200).json(new apiResponse(200, users, "Users fetched successfully"));
});

export const getfeedbacks = asyncHandler(async (req, res) => {
    const feedbacks = await prisma.feedback.findMany({
        select: {
            id: true,
            userId: true,
            title: true,
            details: true,
            user: {
                select: {
                    name: true,
                    lname: true,
                    email: true,
                },
            },
        },
    });
    return res.status(200).json(new apiResponse(200, feedbacks, "Feedbacks fetched successfully"));
});

export const addUser = asyncHandler(async (req, res) => {
    const { name, lname, email} = req.body;
    if (!name || !lname || !email) {
        return res.status(400).json(new apiError(400, "Name, Last Name and Email are required"));
    }
    const existingUser = await prisma.user.findUnique({
        where: { email },
    });
    if (existingUser) {
        return res.status(400).json(new apiError(400, "User with this email already exists"));
    }
    const generatedPassword = Math.random().toString(36).slice(-8);
    const hashedPassword = await bcrypt.hash(generatedPassword, 10);

    const newUser = await prisma.user.create({
        data: {
            name,
            lname,
            email,
            password: hashedPassword,
        },
        select: {
            id: true,
            name: true,
            lname: true,
            email: true,
        },
    });
    return res.status(201).json(new apiResponse(201, newUser, "User added successfully"));
});

export const adminLogin = asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return res.status(400).json(new apiError(400, "Email and password are required"));
    }
    const admin = await prisma.admin.findUnique({
        where: { email },
    });
    const ok = await bcrypt.compare(password, admin.password);
  if (!ok) throw new apiError(401, 'invalid credentials');


  const accessToken = signAccessToken({ userId: admin.id });
  const jti = uuidv4();
  const refreshToken = signRefreshToken({ userId: admin.id, jti });
  await registerRefreshToken(admin.id, jti);


  res.cookie('accessToken', accessToken, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: 'none',
    maxAge: 15 * 60 * 1000, // 15 min
    // domain: COOKIE_DOMAIN,
    path: '/',
  });


  res.cookie('refreshToken', refreshToken, {
    httpOnly: true,
    secure: COOKIE_SECURE,
    sameSite: 'none',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    // domain: COOKIE_DOMAIN,
    path: '/',
  });
    return res.status(200).json(new apiResponse(200, { id: admin.id, email: admin.email, name: admin.name }, "Admin logged in successfully"));
});

export const changeAdminPassword = asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) {
        return res.status(400).json(new apiError(400, "Old password and new password are required"));
    }
    const adminId = req.user?.id;
    const admin = await prisma.admin.findUnique({
        where: { id: adminId },
    });
    const ok = await bcrypt.compare(oldPassword, admin.password);
    if (!ok) {
        return res.status(401).json(new apiError(401, "Old password is incorrect"));
    }
    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await prisma.admin.update({
        where: { id: adminId },
        data: { password: hashedNewPassword },
    });
    return res.status(200).json(new apiResponse(200, {}, "Password changed successfully"));
});


