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

    socket.to(`room:${convoId}`).emit('userJoined', {
      userId,
      convoId
    });

    console.log(`✅ ${userId} joined room: ${convoId}`);
  });

  socket.on('checkOnline', async ({ convoId, memberIds }) => {
    const onlineMembers: string[] = [];
    for (const memberId of memberIds) {
      const isOnline = await redis.exists(`user:online:${memberId}`);
      if (isOnline) {
        onlineMembers.push(memberId);
      }
    }

    socket.to(`room:${convoId}`).emit('onlineMembers', {
      convoId,
      onlineMembers,
    });
  });

  socket.on('leaveRoom', async ({ convoId }) => {
    socket.leave(`room:${convoId}`);
    socket.to(`room:${convoId}`).emit('userLeft', { userId, convoId });
  });

  socket.on('getRoomUsers', async ({ convoId }) => {
    const onlineUsers = await redis.sMembers(`convo:${convoId}:online`);
    socket.emit('roomUsers', { convoId, onlineUsers });
  });

  socket.on('roomUpdate', async ({ convoId, data }) => {
    socket.to(`room:${convoId}`).emit('roomUpdated', data);
  });

  socket.on('newMembersAdded', async ({ convoId, newMember }) => {
    socket.to(`room:${convoId}`).emit('membersAdded', {
      convoId,
      newMember,
    });
  });
};
