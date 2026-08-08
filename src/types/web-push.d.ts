declare module 'web-push' {
  export interface PushSubscription {
    endpoint: string;
    keys: {
      p256dh: string;
      auth: string;
    };
  }

  export interface RequestOptions {
    TTL?: number;
    vapidDetails?: {
      subject: string;
      publicKey: string;
      privateKey: string;
    };
    headers?: Record<string, string>;
  }

  export interface WebPushError extends Error {
    statusCode?: number;
    body?: string;
    headers?: Record<string, string>;
  }

  export function setVapidDetails(subject: string, publicKey: string, privateKey: string): void;

  export function sendNotification(
    subscription: PushSubscription,
    payload?: string | Buffer | null,
    options?: RequestOptions
  ): Promise<unknown>;
}
