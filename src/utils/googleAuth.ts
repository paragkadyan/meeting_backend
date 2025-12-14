import { OAuth2Client } from "google-auth-library";
import { GOOGLE_CLIENT_ID } from "../config/env";
import { apiError } from "./apiError";

const client = new OAuth2Client(GOOGLE_CLIENT_ID);

export const verifyGoogleToken = async (idToken: string) => {
  try{
  const ticket = await client.verifyIdToken({
    idToken,
    audience: GOOGLE_CLIENT_ID,
  });

  const payload = ticket.getPayload();
  if (!payload) throw new apiError(401, "Invalid Google ID token");

  return {
    googleId: payload.sub,
    email: payload.email!,
    name: payload.name,
    picture: payload.picture,
    emailVerified: payload.email_verified,
  };  } catch (error) {
    throw new apiError(500, 'Google token verification failed');
  }
};
