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

/**
 * Returns the remaining lifetime encoded in a JWT.  Cookie and Redis expiry
 * must follow the signed token expiry rather than a separate hard-coded
 * duration, otherwise a valid-looking cookie/session can become unusable
 * earlier than expected.
 */
export function getTokenMaxAge(token: string): number {
    const decoded = jwt.decode(token);
    const exp = typeof decoded === "object" && decoded ? decoded.exp : undefined;

    if (typeof exp !== "number") {
        throw new apiError(500, "Token expiration is missing");
    }

    const maxAge = exp * 1000 - Date.now();
    if (maxAge <= 0) {
        throw new apiError(500, "Token expiration is invalid");
    }

    return maxAge;
}
