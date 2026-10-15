import { Socket } from 'socket.io';
import { redis } from '../db/redis';
import { prisma } from '../db/post';
import { addActiveConversationViewer, removeActiveConversationViewer } from './activeConversation';
import { getParticipantIds, hasConversationAccess, isActiveParticipant } from '../utils/conversationAccess';

const MAX_PRESENCE_LOOKUP = 256;

export const handleRooms = (socket: Socket) => {
  const userId = socket.data.user.id;

  socket.on('joinRoom', async ({ convoId }) => {
    try {
      // Falls back to the DB when the cached participant set is cold, so real
      // members aren't refused just because Redis was flushed.
      if (!(await isActiveParticipant(convoId, userId))) {
        return socket.emit("error", {
          message: "Not authorized to join this conversation"
        });
      }

      socket.join(`room:${convoId}`);
      await addActiveConversationViewer(userId, convoId, socket.id);

      socket.to(`room:${convoId}`).emit('userJoined', {
        userId,
        convoId
      });

      console.log(`✅ ${userId} joined room: ${convoId}`);
    } catch (error) {
      console.error('Join room error:', error);
      socket.emit('error', { message: 'Failed to join conversation' });
    }
  });

  socket.on('checkOnline', async ({ convoId, memberIds }) => {
    try {
      // Only report presence for members of a conversation the caller is in;
      // previously any user's online status could be probed.
      if (!Array.isArray(memberIds) || !(await hasConversationAccess(convoId, userId))) return;

      const participants = new Set(await getParticipantIds(convoId));
      const candidates = memberIds
        .map((id: unknown) => String(id))
        .filter((id: string) => participants.has(id))
        .slice(0, MAX_PRESENCE_LOOKUP);

      const onlineMembers: string[] = [];
      for (const memberId of candidates) {
        const isOnline = await redis.exists(`user:online:${memberId}`);
        if (isOnline) {
          onlineMembers.push(memberId);
        }
      }

      socket.emit('onlineMembers', { convoId, onlineMembers });
    } catch (error) {
      console.error('Check online error:', error);
    }
  });

  socket.on('leaveRoom', async ({ convoId }) => {
    socket.leave(`room:${convoId}`);
    await removeActiveConversationViewer(userId, convoId, socket.id);
    socket.to(`room:${convoId}`).emit('userLeft', { userId, convoId });
  });

  socket.on('getRoomUsers', async ({ convoId }) => {
    if (!(await hasConversationAccess(convoId, userId))) return;
    const onlineUsers = await redis.sMembers(`convo:${convoId}:online`);
    socket.emit('roomUsers', { convoId, onlineUsers });
  });

  // Removed insecure roomUpdate handler - use API endpoint /group-update instead

  // The web client relays this after an admin adds members via the REST API.
  // Only group admins may broadcast it.
  socket.on('newMembersAdded', async ({ convoId, newMember }) => {
    try {
      if (typeof convoId !== 'string' || !convoId) return;
      const participant = await prisma.conversationParticipant.findUnique({
        where: { convoId_userId: { convoId, userId } },
        select: { role: true },
      });
      if (participant?.role !== 'admin') return;

      socket.to(`room:${convoId}`).emit('membersAdded', {
        convoId,
        newMember,
      });
    } catch (error) {
      console.error('New members relay error:', error);
    }
  });
};
