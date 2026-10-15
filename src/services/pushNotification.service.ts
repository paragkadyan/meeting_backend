import webpush, { PushSubscription as WebPushSubscription } from 'web-push';
import { prisma } from '../db/post';
import { logger } from '../logger/logger';
import { sendExpoPush } from './expoPush.service';
import {
  PUSH_NOTIFICATION_BADGE_PATH,
  PUSH_NOTIFICATION_ICON_PATH,
  VAPID_PRIVATE_KEY,
  VAPID_PUBLIC_KEY,
  VAPID_SUBJECT,
} from '../config/env';

type SafePushPayload = {
  title: string;
  body: string;
  icon: string;
  badge: string;
};

const MAX_ATTEMPTS = 3;
const RETRY_BASE_DELAY_MS = 500;
const PUSH_TTL_SECONDS = 60 * 60;
const PUSH_NOTIFICATION_TITLE = 'New Message';
const PUSH_NOTIFICATION_BODY = 'You have a new message';
// Must match the Android channel the app creates (heyllow-mobile notifications setup).
const MOBILE_CHANNEL_ID = 'messages';

const delay = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

class PushNotificationService {
  private readonly enabled: boolean;

  constructor() {
    this.enabled = Boolean(VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY && VAPID_SUBJECT);

    if (this.enabled) {
      webpush.setVapidDetails(VAPID_SUBJECT!, VAPID_PUBLIC_KEY!, VAPID_PRIVATE_KEY!);
    }
  }

  async sendNewMessageNotification(userId: string, context: { convoId?: string } = {}): Promise<void> {
    // Mobile (Expo) and web push are independent: missing VAPID keys only
    // disable the web half.
    await Promise.allSettled([this.sendMobile(userId, context), this.sendWeb(userId)]);
  }

  /**
   * Rings the mobile app when it's in the background (no socket). Phones only:
   * the web gets the socket event. Content-free like message pushes; the app
   * shows the in-app ringing screen on open (or silences this while in front).
   */
  async sendIncomingCallNotification(
    userId: string,
    call: { callId: string; convoId: string; type: 'AUDIO' | 'VIDEO' }
  ): Promise<void> {
    const tokens = await prisma.mobilePushToken.findMany({ where: { userId }, select: { token: true } });
    if (tokens.length === 0) return;

    await sendExpoPush(
      tokens.map(({ token }) => ({
        to: token,
        title: call.type === 'VIDEO' ? 'Incoming video call' : 'Incoming voice call',
        body: 'Open Heyllow to answer',
        data: { type: 'call', callId: call.callId, convoId: call.convoId },
        sound: 'default' as const,
        channelId: MOBILE_CHANNEL_ID,
        priority: 'high' as const,
        // A call rings for 60s; a late notification would be for a call that's over.
        ttl: 60,
      }))
    );
  }

  /** Same generic, content-free wording as web push; tapping opens the chat. */
  private async sendMobile(userId: string, context: { convoId?: string }): Promise<void> {
    const tokens = await prisma.mobilePushToken.findMany({ where: { userId }, select: { token: true } });
    if (tokens.length === 0) return;

    await sendExpoPush(
      tokens.map(({ token }) => ({
        to: token,
        title: PUSH_NOTIFICATION_TITLE,
        body: PUSH_NOTIFICATION_BODY,
        data: { type: 'message', ...(context.convoId && { convoId: context.convoId }) },
        sound: 'default' as const,
        channelId: MOBILE_CHANNEL_ID,
        priority: 'high' as const,
      }))
    );
  }

  private async sendWeb(userId: string): Promise<void> {
    if (!this.enabled) {
      logger.warn('Web push skipped because VAPID configuration is incomplete', { userId });
      return;
    }

    const subscriptions = await prisma.pushSubscription.findMany({ where: { userId } });
    if (subscriptions.length === 0) {
      return;
    }

    const payload: SafePushPayload = {
      title: PUSH_NOTIFICATION_TITLE,
      body: PUSH_NOTIFICATION_BODY,
      icon: PUSH_NOTIFICATION_ICON_PATH,
      badge: PUSH_NOTIFICATION_BADGE_PATH,
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

  private getStatusCode(error: unknown): number | undefined {
    if (typeof error === 'object' && error !== null && 'statusCode' in error) {
      const statusCode = (error as Record<string, unknown>).statusCode;
      return typeof statusCode === 'number' ? statusCode : undefined;
    }
    return undefined;
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
        });

        logger.info('Push notification delivered', { subscriptionId, userId, attempt });
        return;
      } catch (error) {
        const statusCode = this.getStatusCode(error);
        const errorMessage = error instanceof Error ? error.message : String(error);

        if (statusCode === 404 || statusCode === 410) {
          await prisma.pushSubscription.deleteMany({ where: { id: subscriptionId } });
          logger.warn('Removed expired push subscription', { subscriptionId, userId, statusCode });
          return;
        }

        const shouldRetry = statusCode === undefined || statusCode >= 500 || statusCode === 429;
        logger.warn('Push notification delivery failed', {
          subscriptionId,
          userId,
          attempt,
          statusCode,
          error: errorMessage,
          retrying: shouldRetry && attempt < MAX_ATTEMPTS,
        });

        if (!shouldRetry || attempt === MAX_ATTEMPTS) {
          logger.error('Push notification delivery exhausted', { subscriptionId, userId, statusCode, error: errorMessage });
          return;
        }

        await delay(RETRY_BASE_DELAY_MS * 2 ** (attempt - 1));
      }
    }
  }
}

export const pushNotificationService = new PushNotificationService();
