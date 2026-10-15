import { prisma } from '../db/post';
import { EXPO_TOKEN_RE } from '../services/expoPush.service';
import { apiError } from '../utils/apiError';
import { apiResponse } from '../utils/apiResponse';
import { asyncHandler } from '../utils/asyncHandler';

const PLATFORMS = new Set(['ios', 'android']);

const readToken = (body: unknown): string => {
  const token = typeof (body as { token?: unknown })?.token === 'string' ? (body as { token: string }).token.trim() : '';
  if (!EXPO_TOKEN_RE.test(token)) throw new apiError(400, 'A valid Expo push token is required');
  return token;
};

/**
 * Registers this device for push. A token belongs to one device, so if another
 * account signed in on it before, the token moves to the current user.
 */
export const registerMobilePushToken = asyncHandler(async (req, res) => {
  const userId = req.user!.id;
  const token = readToken(req.body);
  const platform = String(req.body?.platform ?? '').toLowerCase();
  if (!PLATFORMS.has(platform)) throw new apiError(400, 'platform must be "ios" or "android"');

  await prisma.mobilePushToken.upsert({
    where: { token },
    update: { userId, platform },
    create: { userId, token, platform },
  });

  return res.status(201).json(new apiResponse(201, { registered: true }, 'Push token registered'));
});

/** Called on sign-out so a signed-out device stops receiving this user's notifications. */
export const deleteMobilePushToken = asyncHandler(async (req, res) => {
  const userId = req.user!.id;
  const token = readToken(req.body);
  await prisma.mobilePushToken.deleteMany({ where: { token, userId } });
  return res.status(200).json(new apiResponse(200, { removed: true }, 'Push token removed'));
});
