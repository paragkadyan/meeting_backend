import { Request } from 'express';
import { prisma } from '../db/post';
import { apiError } from '../utils/apiError';
import { apiResponse } from '../utils/apiResponse';
import { asyncHandler } from '../utils/asyncHandler';

type PushSubscriptionBody = {
  endpoint?: unknown;
  keys?: {
    p256dh?: unknown;
    auth?: unknown;
  };
};

const validatePushSubscription = (body: PushSubscriptionBody) => {
  const endpoint = typeof body.endpoint === 'string' ? body.endpoint.trim() : '';
  const p256dh = typeof body.keys?.p256dh === 'string' ? body.keys.p256dh.trim() : '';
  const auth = typeof body.keys?.auth === 'string' ? body.keys.auth.trim() : '';

  if (!endpoint || !p256dh || !auth) {
    throw new apiError(400, 'A valid push subscription endpoint and keys are required');
  }

  if (!endpoint.startsWith('https://')) {
    throw new apiError(400, 'Push subscription endpoint must use HTTPS');
  }

  return { endpoint, p256dh, auth };
};

const getUserAgent = (req: Request) => {
  const userAgent = req.get('user-agent');
  return userAgent ? userAgent.slice(0, 512) : null;
};

export const registerPushSubscription = asyncHandler(async (req, res) => {
  const userId = req.user!.id;
  const subscription = validatePushSubscription(req.body);

  const savedSubscription = await prisma.pushSubscription.upsert({
    where: { endpoint: subscription.endpoint },
    update: {
      userId,
      p256dh: subscription.p256dh,
      auth: subscription.auth,
      userAgent: getUserAgent(req),
    },
    create: {
      userId,
      endpoint: subscription.endpoint,
      p256dh: subscription.p256dh,
      auth: subscription.auth,
      userAgent: getUserAgent(req),
    },
    select: { id: true, endpoint: true, createdAt: true, updatedAt: true },
  });

  return res.status(201).json(new apiResponse(201, savedSubscription, 'Push subscription registered'));
});

export const updatePushSubscription = asyncHandler(async (req, res) => {
  const userId = req.user!.id;
  const { subscriptionId } = req.params;
  const subscription = validatePushSubscription(req.body);

  const updatedSubscription = await prisma.pushSubscription.updateMany({
    where: { id: subscriptionId, userId },
    data: {
      endpoint: subscription.endpoint,
      p256dh: subscription.p256dh,
      auth: subscription.auth,
      userAgent: getUserAgent(req),
    },
  });

  if (updatedSubscription.count === 0) {
    throw new apiError(404, 'Push subscription not found');
  }

  return res.status(200).json(new apiResponse(200, { id: subscriptionId }, 'Push subscription updated'));
});

export const deletePushSubscription = asyncHandler(async (req, res) => {
  const userId = req.user!.id;
  const { subscriptionId } = req.params;

  const deletedSubscription = await prisma.pushSubscription.deleteMany({
    where: { id: subscriptionId, userId },
  });

  if (deletedSubscription.count === 0) {
    throw new apiError(404, 'Push subscription not found');
  }

  return res.status(200).json(new apiResponse(200, { id: subscriptionId }, 'Push subscription deleted'));
});
