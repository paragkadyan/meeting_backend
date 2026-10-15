import { prisma } from '../db/post';
import { redis } from '../db/redis';
import { apiError } from './apiError';

/**
 * Two levels of conversation access:
 *
 *  - Participant: a current member (row in ConversationParticipant). Required
 *    to *act* in a conversation: send, react, type, edit, delete, join the room.
 *  - Access: ever a member (row in ConversationByUser). Ex-members keep that
 *    row when they leave a group, so they can still *read* past history, as
 *    the web client already allows.
 */

const participantsKey = (convoId: string) => `convo:${convoId}:participants`;

const isId = (value: unknown): value is string => typeof value === 'string' && value.length > 0;

/**
 * Participant IDs for a conversation, served from the Redis set and loaded
 * from the database (and cached) when the set is cold.
 */
export async function getParticipantIds(convoId: string): Promise<string[]> {
  const cached = await redis.sMembers(participantsKey(convoId));
  if (cached.length > 0) return cached;

  const rows = await prisma.conversationParticipant.findMany({
    where: { convoId },
    select: { userId: true },
  });
  const ids = rows.map((r) => r.userId);
  if (ids.length > 0) await redis.sAdd(participantsKey(convoId), ids);
  return ids;
}

export async function isActiveParticipant(convoId: unknown, userId: string): Promise<boolean> {
  if (!isId(convoId)) return false;
  if (await redis.sIsMember(participantsKey(convoId), userId)) return true;

  // Not in the cached set: the set may be cold, so confirm against the DB.
  // Don't add the user to the set here; a partial set would make other code
  // treat it as complete and skip the DB load.
  const row = await prisma.conversationParticipant.findUnique({
    where: { convoId_userId: { convoId, userId } },
    select: { userId: true },
  });
  return Boolean(row);
}

export async function hasConversationAccess(convoId: unknown, userId: string): Promise<boolean> {
  if (!isId(convoId)) return false;
  const row = await prisma.conversationByUser.findUnique({
    where: { userId_convoId: { userId, convoId } },
    select: { userId: true },
  });
  return Boolean(row);
}

/** For REST handlers. 404 rather than 403 so conversation IDs can't be probed. */
export async function assertConversationAccess(convoId: unknown, userId: string): Promise<void> {
  if (!(await hasConversationAccess(convoId, userId))) {
    throw new apiError(404, 'Conversation not found');
  }
}
