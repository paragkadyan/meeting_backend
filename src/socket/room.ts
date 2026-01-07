import { Socket, Server } from 'socket.io';
import { cassandra } from '../db/cassa';
import { redis } from '../db/redis';

export const handleRooms = (socket: Socket) => {
  const userId = socket.data.user.id;

  socket.on('joinRoom', async ({ convoId }) => {

    const isMember = await redis.sIsMember(
      `convo:${convoId}:participants`,
      userId
    );

    if (!isMember) {
      return socket.emit("error", {
        message: "Not authorized to join this conversation"
      });
    }

    socket.join(`room:${convoId}`);

    await redis.sAdd(`user:${userId}:joinedConversations`,convoId);

    //await redis.sAdd(`convo:${convoId}:online`, userId);

    socket.to(`room:${convoId}`).emit('userJoined', {
      userId,
      convoId
    });

    console.log(`✅ ${userId} joined room: ${convoId}`);
  });

  socket.on('leaveRoom', async ({ convoId }) => {
    socket.leave(`room:${convoId}`);
    await redis.sRem(`convo:${convoId}:online`, userId);
    socket.to(`room:${convoId}`).emit('userLeft', { userId, convoId });
  });

  socket.on('getRoomUsers', async ({ convoId }) => {
    const onlineUsers = await redis.sMembers(`convo:${convoId}:online`);
    socket.emit('roomUsers', { convoId, onlineUsers });
  });
};
