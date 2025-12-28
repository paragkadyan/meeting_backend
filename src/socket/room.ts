import { Socket, Server } from 'socket.io';
import { cassandra } from '../db/cassa';
import { redis } from '../db/redis';

export const handleRooms = (socket: Socket) => {
  const userId = socket.data.user.id;

  // Join conversation room
  socket.on('joinRoom', async ({ convoId }) => {
    socket.join(`room:${convoId}`);
    
    // Add to user's conversation list
    await redis.sadd(`user:${userId}:conversations`, convoId);
    
    // Track user in room
    await redis.sadd(`convo:${convoId}:online`, userId);
    
    socket.to(`room:${convoId}`).emit('userJoined', { 
      userId, 
      convoId 
    });
    
    console.log(`✅ ${userId} joined room: ${convoId}`);
  });

  // Leave room
  socket.on('leaveRoom', async ({ convoId }) => {
    socket.leave(`room:${convoId}`);
    await redis.srem(`convo:${convoId}:online`, userId);
    socket.to(`room:${convoId}`).emit('userLeft', { userId, convoId });
  });

  // Get room users
  socket.on('getRoomUsers', async ({ convoId }) => {
    const onlineUsers = await redis.smembers(`convo:${convoId}:online`);
    socket.emit('roomUsers', { convoId, onlineUsers });
  });
};
