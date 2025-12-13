import jwt, { Secret, SignOptions, JwtPayload } from "jsonwebtoken";
import {
    JWT_ACCESS_SECRET,
    JWT_REFRESH_SECRET,
    ACCESS_TOKEN_EXPIRES_IN,
    REFRESH_TOKEN_EXPIRES_IN,
} from "../config/env";
import { apiError } from "./apiError";



export interface AccessTokenPayload extends JwtPayload {
    userId: string;
}

export interface RefreshTokenPayload extends JwtPayload {
    userId: string;
    jti: string;
}



export function signAccessToken(payload: AccessTokenPayload): string {
    try{
    return jwt.sign(
        payload,
        JWT_ACCESS_SECRET as Secret,
        {
            expiresIn: ACCESS_TOKEN_EXPIRES_IN as SignOptions["expiresIn"],
        }
    );}catch(err){
        throw new apiError(500, "Error signing access token");
    }
}

export function signRefreshToken(payload: RefreshTokenPayload): string {
    try{
    return jwt.sign(
        payload,
        JWT_REFRESH_SECRET as Secret,
        {
            expiresIn: REFRESH_TOKEN_EXPIRES_IN as SignOptions["expiresIn"],
        }
    ); } catch(err){
        throw new apiError(500, "Error signing refresh token");
    }
}



export function verifyAccessToken(token: string): AccessTokenPayload {
    try {
        return jwt.verify(token, JWT_ACCESS_SECRET as Secret) as AccessTokenPayload;
    } catch (err) {
       throw new apiError(401, "Invalid or expired access token");
    }
}

export function verifyRefreshToken(token: string): RefreshTokenPayload {
    try {
        return jwt.verify(token, JWT_REFRESH_SECRET as Secret) as RefreshTokenPayload;
    } catch (err) {
        throw new apiError(401, "Invalid or expired refresh token");
    }
}