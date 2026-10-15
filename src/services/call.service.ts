import { randomUUID } from "crypto";
import { CallParticipantStatus, CallStatus } from "../../generated/prisma/client";
import { prisma } from "../db/post";
import { getIO } from "../socket";
import { apiError } from "../utils/apiError";
import { closeLiveKitRoomIfPresent, createParticipantToken } from "./livekit.service";

const terminalCallStatuses: CallStatus[] = [
  CallStatus.ENDED,
  CallStatus.REJECTED,
  CallStatus.MISSED,
  CallStatus.CANCELLED,
];

type CallEvent =
  | "callIncoming"
  | "callRinging"
  | "callAccepted"
  | "callActive"
  | "callRejected"
  | "callBusy"
  | "callCancelled"
  | "callEnded"
  | "callMissed";

async function emitToCallParticipants(
  callId: string,
  event: CallEvent,
  payload: Record<string, unknown> = {}
) {
  const participants = await prisma.callParticipant.findMany({
    where: { callId },
    select: { userId: true },
  });
  const io = getIO();
  for (const participant of participants) {
    io.to(`user:${participant.userId}`).emit(event, { callId, ...payload });
  }
}

export async function startCall(convoId: string, userId: string) {
  if (!convoId) throw new apiError(400, "conversationId is required");

  const conversation = await prisma.conversation.findUnique({
    where: { id: convoId },
    select: { id: true, participants: { select: { userId: true } } },
  });
  if (!conversation) throw new apiError(404, "Conversation not found");
  if (!conversation.participants.some((participant) => participant.userId === userId)) {
    throw new apiError(403, "You are not a participant of this conversation");
  }
  if (conversation.participants.length < 2) throw new apiError(400, "Calls require at least two conversation participants");

  const callId = randomUUID();
  const roomName = `conversation-${convoId}-call-${callId}`;
  const call = await prisma.call.create({
    data: {
      id: callId,
      convoId,
      roomName,
      initiatedBy: userId,
      participants: {
        create: conversation.participants.map(({ userId: participantId }) => ({
          userId: participantId,
          status: participantId === userId
            ? CallParticipantStatus.ACCEPTED
            : CallParticipantStatus.RINGING,
        })),
      },
    },
    include: { participants: { select: { userId: true } } },
  });

  const io = getIO();
  for (const participant of call.participants) {
    if (participant.userId === userId) continue;
    io.to(`user:${participant.userId}`).emit("callIncoming", {
      callId: call.id,
      conversationId: call.convoId,
      initiatedBy: userId,
      createdAt: call.createdAt,
    });
  }
  io.to(`user:${userId}`).emit("callRinging", {
    callId: call.id,
    conversationId: call.convoId,
    createdAt: call.createdAt,
  });

  return call;
}

export async function createCallParticipantToken(callId: string, userId: string) {
  const call = await prisma.call.findUnique({
    where: { id: callId },
    include: { participants: { where: { userId }, take: 1 } },
  });
  if (!call) throw new apiError(404, "Call not found");
  if (terminalCallStatuses.includes(call.status)) throw new apiError(409, "Call has ended");

  const membership = await prisma.conversationParticipant.findUnique({
    where: { convoId_userId: { convoId: call.convoId, userId } },
    select: { userId: true },
  });
  const participant = call.participants[0];
  if (!membership || !participant) throw new apiError(403, "You are not invited to this call");
  const joinableStatuses: CallParticipantStatus[] = [
    CallParticipantStatus.ACCEPTED,
    CallParticipantStatus.JOINED,
    CallParticipantStatus.LEFT,
  ];
  if (!joinableStatuses.includes(participant.status)) {
    throw new apiError(403, "Accept the call before joining");
  }

  const credentials = await createParticipantToken(userId, call.roomName);
  return { ...credentials, callId: call.id };
}

async function getCallParticipant(callId: string, userId: string) {
  const call = await prisma.call.findUnique({
    where: { id: callId },
    include: { participants: { where: { userId }, take: 1 } },
  });
  if (!call) throw new apiError(404, "Call not found");
  const participant = call.participants[0];
  if (!participant) throw new apiError(403, "You are not a participant of this call");
  return { call, participant };
}

async function updateAfterInviteResponse(callId: string) {
  const participants = await prisma.callParticipant.findMany({
    where: { callId },
    select: { userId: true, status: true, call: { select: { initiatedBy: true } } },
  });
  const invitees = participants.filter((participant) => participant.userId !== participant.call.initiatedBy);
  if (
    invitees.length > 0 &&
    invitees.every((participant) =>
      ([CallParticipantStatus.REJECTED, CallParticipantStatus.BUSY] as CallParticipantStatus[]).includes(participant.status)
    )
  ) {
    await prisma.call.updateMany({
      where: { id: callId, status: CallStatus.RINGING },
      data: { status: CallStatus.REJECTED, endedAt: new Date() },
    });
  }
}

export async function respondToCall(
  callId: string,
  userId: string,
  response: "accept" | "reject" | "busy"
) {
  const { call, participant } = await getCallParticipant(callId, userId);
  if (call.status !== CallStatus.RINGING || participant.status !== CallParticipantStatus.RINGING) {
    throw new apiError(409, "Call response is not valid in the current state");
  }

  const nextStatus = response === "accept"
    ? CallParticipantStatus.ACCEPTED
    : response === "busy"
      ? CallParticipantStatus.BUSY
      : CallParticipantStatus.REJECTED;
  const result = await prisma.callParticipant.updateMany({
    where: { callId, userId, status: CallParticipantStatus.RINGING },
    data: { status: nextStatus },
  });
  if (!result.count) throw new apiError(409, "Call response is not valid in the current state");
  await updateAfterInviteResponse(callId);

  const event: CallEvent = response === "accept" ? "callAccepted" : response === "busy" ? "callBusy" : "callRejected";
  await emitToCallParticipants(callId, event, { userId });
  return { callId, userId, status: nextStatus };
}

export async function cancelCall(callId: string, userId: string) {
  const { call } = await getCallParticipant(callId, userId);
  if (call.initiatedBy !== userId) throw new apiError(403, "Only the caller can cancel this call");
  if (call.status === CallStatus.RINGING) {
    const result = await prisma.call.updateMany({
      where: { id: callId, status: CallStatus.RINGING },
      data: { status: CallStatus.CANCELLED, endedAt: new Date() },
    });
    if (!result.count) {
      const latest = await prisma.call.findUnique({ where: { id: callId }, select: { status: true } });
      if (latest?.status !== CallStatus.CANCELLED) throw new apiError(409, "Only a ringing call can be cancelled");
    }
  } else if (call.status !== CallStatus.CANCELLED) {
    throw new apiError(409, "Only a ringing call can be cancelled");
  }
  // Mark it terminal first, so a late participant-joined webhook cannot reactivate it.
  // Retrying this endpoint also retries room closure if LiveKit was temporarily unavailable.
  await closeLiveKitRoomIfPresent(call.roomName);
  await prisma.callParticipant.updateMany({
    where: { callId, status: CallParticipantStatus.RINGING },
    data: { status: CallParticipantStatus.MISSED },
  });
  await emitToCallParticipants(callId, "callCancelled", { userId });
  return { callId, status: CallStatus.CANCELLED };
}

export async function endCall(callId: string, userId: string) {
  const { call, participant } = await getCallParticipant(callId, userId);
  if (call.status !== CallStatus.ACTIVE && call.status !== CallStatus.ENDED) {
    throw new apiError(409, "Only an active call can be ended");
  }
  const endableStatuses: CallParticipantStatus[] = [CallParticipantStatus.JOINED];
  if (!endableStatuses.includes(participant.status)) {
    throw new apiError(403, "Only a participant currently in the call can end it");
  }
  if (call.status === CallStatus.ACTIVE) {
    const result = await prisma.call.updateMany({
      where: { id: callId, status: CallStatus.ACTIVE },
      data: { status: CallStatus.ENDED, endedAt: new Date() },
    });
    if (!result.count) {
      const latest = await prisma.call.findUnique({ where: { id: callId }, select: { status: true } });
      if (latest?.status !== CallStatus.ENDED) throw new apiError(409, "Call has already ended");
    }
  }
  await closeLiveKitRoomIfPresent(call.roomName);
  await prisma.callParticipant.updateMany({
    where: { callId, status: CallParticipantStatus.RINGING },
    data: { status: CallParticipantStatus.MISSED },
  });
  await emitToCallParticipants(callId, "callEnded", { userId });
  return { callId, status: CallStatus.ENDED };
}

export async function listConversationCalls(convoId: string, userId: string) {
  if (!convoId) throw new apiError(400, "conversationId is required");
  const membership = await prisma.conversationParticipant.findUnique({
    where: { convoId_userId: { convoId, userId } },
    select: { userId: true },
  });
  if (!membership) throw new apiError(403, "You are not a participant of this conversation");
  return prisma.call.findMany({
    where: { convoId },
    orderBy: { createdAt: "desc" },
    take: 50,
    select: {
      id: true,
      convoId: true,
      initiatedBy: true,
      status: true,
      startedAt: true,
      endedAt: true,
      createdAt: true,
      participants: { select: { userId: true, status: true, joinedAt: true, leftAt: true } },
    },
  });
}

export async function handleLiveKitWebhook(event: {
  event?: string;
  room?: { name?: string };
  participant?: { identity?: string };
}) {
  const roomName = event.room?.name;
  if (!roomName) return;
  const call = await prisma.call.findUnique({ where: { roomName }, select: { id: true, status: true } });
  if (!call) return;

  if (event.event === "participant_joined" && event.participant?.identity) {
    if (terminalCallStatuses.includes(call.status)) {
      await closeLiveKitRoomIfPresent(roomName);
      return;
    }
    const userId = event.participant.identity;
    const joined = await prisma.callParticipant.updateMany({
      where: { callId: call.id, userId, status: { in: [CallParticipantStatus.ACCEPTED, CallParticipantStatus.LEFT] } },
      data: { status: CallParticipantStatus.JOINED, joinedAt: new Date(), leftAt: null },
    });
    if (!joined.count) return;
    await prisma.call.updateMany({
      where: { id: call.id, status: CallStatus.RINGING },
      data: { status: CallStatus.ACTIVE, startedAt: new Date() },
    });
    await emitToCallParticipants(call.id, "callActive", { userId, status: CallStatus.ACTIVE });
  } else if (event.event === "participant_left" && event.participant?.identity) {
    const userId = event.participant.identity;
    await prisma.callParticipant.updateMany({
      where: { callId: call.id, userId, status: CallParticipantStatus.JOINED },
      data: { status: CallParticipantStatus.LEFT, leftAt: new Date() },
    });
  } else if (event.event === "room_finished" && !terminalCallStatuses.includes(call.status)) {
    const nextStatus = call.status === CallStatus.RINGING ? CallStatus.MISSED : CallStatus.ENDED;
    const result = await prisma.call.updateMany({
      where: { id: call.id, status: { in: [CallStatus.RINGING, CallStatus.ACTIVE] } },
      data: { status: nextStatus, endedAt: new Date() },
    });
    if (result.count) {
      await prisma.callParticipant.updateMany({
        where: { callId: call.id, status: { in: [CallParticipantStatus.RINGING, CallParticipantStatus.ACCEPTED] } },
        data: { status: CallParticipantStatus.MISSED },
      });
      await emitToCallParticipants(call.id, nextStatus === CallStatus.MISSED ? "callMissed" : "callEnded", {
        status: nextStatus,
      });
    }
  }
}

export async function markTimedOutCallsMissed() {
  const cutoff = new Date(Date.now() - 60_000);
  const staleCalls = await prisma.call.findMany({
    where: { status: CallStatus.RINGING, createdAt: { lt: cutoff } },
    select: { id: true },
    take: 100,
  });
  for (const call of staleCalls) {
    const result = await prisma.call.updateMany({
      where: { id: call.id, status: CallStatus.RINGING, createdAt: { lt: cutoff } },
      data: { status: CallStatus.MISSED, endedAt: new Date() },
    });
    if (!result.count) continue;
    await prisma.callParticipant.updateMany({
      where: { callId: call.id, status: { in: [CallParticipantStatus.RINGING, CallParticipantStatus.ACCEPTED] } },
      data: { status: CallParticipantStatus.MISSED },
    });
    await emitToCallParticipants(call.id, "callMissed", { status: CallStatus.MISSED });
  }
}

export function startCallTimeoutWorker() {
  const run = () => {
    void markTimedOutCallsMissed().catch((error) => {
      console.error("Call timeout processing failed", error);
    });
  };
  const timer = setInterval(run, 15_000);
  timer.unref();
}
