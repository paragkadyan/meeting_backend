export const handleRooms = (socket: any) => {
  socket.on("join_convos", (convoIds: string[]) => {
    convoIds.forEach(id => {
      socket.join(`convo:${id}`);
    });
  });
};
