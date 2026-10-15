import { Server } from 'socket.io';
import { redis } from '../db/redis';
import { logger } from '../logger/logger';

/**
 * Presence is tracked in Redis sets of socket IDs, cleaned up in each socket's
 * `disconnect` handler. When a server process dies (crash, deploy, dev
 * restart) those handlers never run, so dead socket IDs pile up. The result:
 * users look online for longer, "last seen" stops updating, and they count as
 * "viewing" chats, which suppresses push notifications.
 *
 * At startup, remove socket IDs that no server in the cluster holds.
 */

const USER_SOCKETS = 'user:sockets:*';
const VIEWER_SOCKETS = 'convo:*:activeViewerSockets:*';

async function scanKeys(pattern: string): Promise<string[]> {
  const keys: string[] = [];
  // node-redis v5 yields batches of keys.
  for await (const batch of redis.scanIterator({ MATCH: pattern, COUNT: 500 })) {
    keys.push(...(Array.isArray(batch) ? batch : [batch]));
  }
  return keys;
}

export async function prunePresence(io: Server): Promise<void> {
  // Snapshot the recorded IDs *before* asking which sockets are live, so a
  // socket that connects mid-run is never mistaken for a dead one.
  const userKeys = await scanKeys(USER_SOCKETS);
  const viewerKeys = await scanKeys(VIEWER_SOCKETS);
  const snapshot = new Map<string, string[]>();
  for (const key of [...userKeys, ...viewerKeys]) snapshot.set(key, await redis.sMembers(key));

  // Cluster-wide via the Redis adapter; throws if another node doesn't answer,
  // in which case we skip rather than risk removing live sockets.
  const live = new Set((await io.fetchSockets()).map((s) => s.id));

  let removed = 0;
  for (const key of userKeys) {
    const stale = (snapshot.get(key) ?? []).filter((id) => !live.has(id));
    if (!stale.length) continue;
    await redis.sRem(key, stale);
    removed += stale.length;
    if ((await redis.sCard(key)) === 0) {
      // Same end state as a normal last disconnect (socket/presence.ts).
      const userId = key.slice('user:sockets:'.length);
      await redis.multi().del(`user:online:${userId}`).del(key).set(`user:lastSeen:${userId}`, Date.now().toString()).exec();
    }
  }

  for (const key of viewerKeys) {
    const stale = (snapshot.get(key) ?? []).filter((id) => !live.has(id));
    if (!stale.length) continue;
    await redis.sRem(key, stale);
    removed += stale.length;
    if ((await redis.sCard(key)) === 0) {
      // convo:<convoId>:activeViewerSockets:<userId> (see socket/activeConversation.ts)
      const [, convoId, , userId] = key.split(':');
      await redis.multi().del(key).sRem(`convo:${convoId}:activeViewers`, userId).sRem(`user:${userId}:activeConvos`, convoId).exec();
    }
  }

  logger.info('Presence cleanup finished', { removedSocketIds: removed, liveSockets: live.size });
}
