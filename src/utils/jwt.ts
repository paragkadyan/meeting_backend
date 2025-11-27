import jwt, { Secret } from "jsonwebtoken";
import {
    JWT_ACCESS_SECRET,
    JWT_REFRESH_SECRET,
    ACCESS_TOKEN_EXPIRES_IN,
    REFRESH_TOKEN_EXPIRES_IN,
} from "../config/env";

// ---- Payload Types ----
export interface AccessPayload {
    userId: string;
}

export interface RefreshPayload {
    userId: string;
    jti: string; // unique token id for refresh token
}

// ---- Token Signers ----
export function signAccessToken(payload: AccessPayload): string {
    return jwt.sign(
        payload,
        JWT_ACCESS_SECRET as unknown as Secret, // changed: cast to Secret
        {
            expiresIn: ACCESS_TOKEN_EXPIRES_IN as unknown as jwt.SignOptions['expiresIn'], // changed: cast to expected type
        }
    );
}

export function signRefreshToken(payload: RefreshPayload): string {
    return jwt.sign(
        payload,
        JWT_REFRESH_SECRET as unknown as Secret, // changed: cast to Secret
        {
            expiresIn: REFRESH_TOKEN_EXPIRES_IN as unknown as jwt.SignOptions['expiresIn'], // changed: cast to expected type
        }
    );
}

// ---- Token Verifiers ----
export function verifyAccessToken(token: string): AccessPayload {
    return jwt.verify(
        token,
        JWT_ACCESS_SECRET as Secret
    ) as AccessPayload;
}

export function verifyRefreshToken(token: string): RefreshPayload {
    return jwt.verify(
        token,
        JWT_REFRESH_SECRET as Secret
    ) as RefreshPayload;
}
