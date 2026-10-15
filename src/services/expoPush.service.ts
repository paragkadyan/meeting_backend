import { prisma } from '../db/post';
import { logger } from '../logger/logger';

/**
 * Sends notifications to the mobile app through Expo's push service, which
 * forwards to FCM (Android) and APNs (iOS).
 * Docs: https://docs.expo.dev/push-notifications/sending-notifications/
 */

const EXPO_PUSH_URL = 'https://exp.host/--/api/v2/push/send';
const MAX_BATCH = 100; // Expo rejects larger batches (PUSH_TOO_MANY_NOTIFICATIONS)

export const EXPO_TOKEN_RE = /^Expo(nent)?PushToken\[[A-Za-z0-9_-]+\]$/;

type ExpoMessage = {
  to: string;
  title: string;
  body: string;
  data?: Record<string, unknown>;
  sound?: 'default';
  channelId?: string;
  priority?: 'default' | 'normal' | 'high';
};

type ExpoTicket =
  | { status: 'ok'; id: string }
  | { status: 'error'; message: string; details?: { error?: string } };

export async function sendExpoPush(messages: ExpoMessage[]): Promise<void> {
  for (let i = 0; i < messages.length; i += MAX_BATCH) {
    const batch = messages.slice(i, i + MAX_BATCH);
    try {
      const res = await fetch(EXPO_PUSH_URL, {
        method: 'POST',
        headers: { accept: 'application/json', 'content-type': 'application/json' },
        body: JSON.stringify(batch),
      });
      if (!res.ok) {
        logger.warn('Expo push request failed', { status: res.status, body: (await res.text()).slice(0, 500) });
        continue;
      }
      const { data: tickets } = (await res.json()) as { data: ExpoTicket[] };

      // Tickets come back in the same order as the messages.
      const deadTokens: string[] = [];
      tickets.forEach((ticket, idx) => {
        if (ticket.status !== 'error') return;
        if (ticket.details?.error === 'DeviceNotRegistered') {
          deadTokens.push(batch[idx].to);
        } else {
          logger.warn('Expo push ticket error', { error: ticket.details?.error, message: ticket.message });
        }
      });

      if (deadTokens.length) {
        await prisma.mobilePushToken.deleteMany({ where: { token: { in: deadTokens } } });
        logger.info('Removed unregistered Expo push tokens', { count: deadTokens.length });
      }
    } catch (error) {
      logger.warn('Expo push send threw', { error: error instanceof Error ? error.message : String(error) });
    }
  }
}
