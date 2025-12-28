import { cassandra } from "../db/cassa";

export const handleOfflineSync = (socket: any) => {
  socket.on("sync_messages", async () => {
    const userId = socket.data.userId;

    const result = await cassandra.execute(
      `SELECT * FROM messages WHERE receiver_id=? AND delivered=false`,
      [userId],
      { prepare: true }
    );

    socket.emit("sync_messages", result.rows);

    // mark delivered
    for (const msg of result.rows) {
      await cassandra.execute(
        `UPDATE messages SET delivered=true WHERE id=?`,
        [msg.id],
        { prepare: true }
      );
    }
  });
};
