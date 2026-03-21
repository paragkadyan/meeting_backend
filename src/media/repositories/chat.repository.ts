import prisma from "../../db/post";

export async function isUserInChat(chatId: string, userId: string): Promise<boolean> {
  const participant = await prisma.conversationParticipant.findUnique({
    where: {
      convoId_userId: {
        convoId: chatId,
        userId,
      },
    },
    select: { userId: true },
  });

  return Boolean(participant);
}
