import { cassandra } from "../db/cassa";
import { redis } from "../db/redis";

export const handleMessages = (io: any, socket: any) => {
  interface MessagePayload {
    convoId: string;
    content: string;
  }
  

  socket.on("send_message", async (payload: MessagePayload) => {
    const { convoId, content } = payload;
    const senderId = socket.data.userId;

    const message = {
      convo_id: convoId,
      sender_id: senderId,
      content,
      created_at: new Date(),
      delivered: false,
    };

    // 1️⃣ Save message
    await cassandra.execute(
      `INSERT INTO messages (convo_id, sender_id, content, created_at, delivered)
       VALUES (?, ?, ?, ?, ?)`,
      [
        message.convo_id,
        message.sender_id,
        message.content,
        message.created_at,
        message.delivered,
      ],
      { prepare: true }
    );

    // 2️⃣ Emit to room (works across servers via Redis)
    io.to(`convo:${convoId}`).emit("new_message", message);

    // 3️⃣ Handle offline users
    await markDelivery(convoId, message);
  });
};
