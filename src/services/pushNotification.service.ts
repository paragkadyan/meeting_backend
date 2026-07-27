import webpush, { PushSubscription as WebPushSubscription, WebPushError } from 'web-push';
import { prisma } from '../db/post';
import { logger } from '../logger/logger';
import {
  PUSH_NOTIFICATION_BADGE_URL,
  PUSH_NOTIFICATION_ICON_URL,
  PUSH_NOTIFICATION_TITLE,
  VAPID_PRIVATE_KEY,
  VAPID_PUBLIC_KEY,
  VAPID_SUBJECT,
} from '../config/env';

type SafePushPayload = {
  title: string;
  body: 'You have a new message';
  icon?: string;
  badge?: string;
  timestamp: string;
};

const MAX_ATTEMPTS = 3;
const RETRY_BASE_DELAY_MS = 500;
const PUSH_TTL_SECONDS = 60 * 60;

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

class PushNotificationService {
  private readonly enabled: boolean;

  constructor() {
    this.enabled = Boolean(VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY && VAPID_SUBJECT);
  }

  async sendNewMessageNotification(userId: string): Promise<void> {
    if (!this.enabled) {
      logger.warn('Push notification skipped because VAPID configuration is incomplete', { userId });
      return;
    }

    const subscriptions = await prisma.pushSubscription.findMany({ where: { userId } });
    if (subscriptions.length === 0) {
      return;
    }

    const payload: SafePushPayload = {
      title: PUSH_NOTIFICATION_TITLE,
      body: 'You have a new message',
      icon: PUSH_NOTIFICATION_ICON_URL,
      badge: PUSH_NOTIFICATION_BADGE_URL,
      timestamp: new Date().toISOString(),
    };

    await Promise.allSettled(
      subscriptions.map((subscription) =>
        this.deliverWithRetry(subscription.id, userId, {
          endpoint: subscription.endpoint,
          keys: {
            p256dh: subscription.p256dh,
            auth: subscription.auth,
          },
        }, payload)
      )
    );
  }

  private async deliverWithRetry(
    subscriptionId: string,
    userId: string,
    subscription: WebPushSubscription,
    payload: SafePushPayload
  ): Promise<void> {
    for (let attempt = 1; attempt <= MAX_ATTEMPTS; attempt += 1) {
      try {
        await webpush.sendNotification(subscription, JSON.stringify(payload), {
          TTL: PUSH_TTL_SECONDS,
          vapidDetails: {
            subject: VAPID_SUBJECT!,
            publicKey: VAPID_PUBLIC_KEY!,
            privateKey: VAPID_PRIVATE_KEY!,
          },
        });
        logger.info('Push notification delivered', { subscriptionId, userId, attempt });
        return;
      } catch (error) {
        const pushError = error as WebPushError;
        if (pushError.statusCode === 404 || pushError.statusCode === 410) {
          await prisma.pushSubscription.deleteMany({ where: { id: subscriptionId } });
          logger.warn('Removed expired push subscription', { subscriptionId, userId, statusCode: pushError.statusCode });
          return;
        }

        const shouldRetry = !pushError.statusCode || pushError.statusCode >= 500 || pushError.statusCode === 429;
        logger.warn('Push notification delivery failed', { subscriptionId, userId, attempt, statusCode: pushError.statusCode, retrying: shouldRetry && attempt < MAX_ATTEMPTS });

        if (!shouldRetry || attempt === MAX_ATTEMPTS) {
          logger.error('Push notification delivery exhausted', { subscriptionId, userId, statusCode: pushError.statusCode });
          return;
        }

        await delay(RETRY_BASE_DELAY_MS * 2 ** (attempt - 1));
      }
    }
  }
}

export const pushNotificationService = new PushNotificationService();
