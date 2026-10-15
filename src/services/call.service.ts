import { randomUUID } from "crypto";
import { CallParticipantStatus, CallStatus, CallType } from "../../generated/prisma/client";
import { prisma } from "../db/post";
import { getIO } from "../socket";
import { apiError } from "../utils/apiError";
import { logger } from "../logger/logger";
import { closeLiveKitRoomIfPresent, createParticipantToken, getRoomOccupancy } from "./livekit.service";

/**
 * Call lifecycle
 *
 *  Call:        RINGING ──(an invitee accepts)──▶ ACTIVE ──▶ ENDED
 *                  └──▶ CANCELLED (caller hung up) | REJECTED (everyone declined/busy) | MISSED (no answer)
 *
 *  Participant: RINGING ──▶ ACCEPTED ──(connected to LiveKit)──▶ JOINED ──▶ LEFT
 *                  └──▶ REJECTED | BUSY | MISSED          (group members can still join later)
 *
 * State changes come from the REST/socket actions below and, when configured,
 * LiveKit webhooks. The call ends itself once fewer than two people are in it
 * and nobody is still being rung (settleCall), so it does not depend on webhooks.
 *
 * Socket events (to `user:<id>` rooms):
 *  callIncoming          → invitees      { callId, conversationId, initiatedBy, type, isGroup, createdAt }
 *  callRinging           → caller        { callId, conversationId, type, isGroup, createdAt }
 *  callParticipantUpdate → all invited   { callId, userId, status, callStatus }
 *  callEnded             → all invited   { callId, status }
 */

const RING_TIMEOUT_MS = 60_000;
/** An answered call whose LiveKit room stays empty this long is treated as abandoned. */
const EMPTY_ROOM_GRACE_MS = 45_000;
const SWEEP_INTERVAL_MS = 10_000;

const terminalCallStatuses: CallStatus[] = [
  CallStatus.ENDED,
  CallStatus.REJECTED,
  CallStatus.MISSED,
  CallStatus.CANCELLED,
];
const openCallStatuses: CallStatus[] = [CallStatus.RINGING, CallStatus.ACTIVE];
const inCallStatuses: CallParticipantStatus[] = [CallParticipantStatus.ACCEPTED, CallParticipantStatus.JOINED];

const isTerminal = (status: CallStatus) => terminalCallStatuses.includes(status);

function emitToUsers(userIds: string[], event: string, payload: Record<string, unknown>) {
  const io = getIO();
  for (const userId of userIds) io.to(`user:${userId}`).emit(event, payload);
}

async function getParticipantIds(callId: string) {
  const participants = await prisma.callParticipant.findMany({ where: { callId }, select: { userId: true } });
  return participants.map((participant) => participant.userId);
}

async function emitParticipantUpdate(callId: string, userId: string, status: CallParticipantStatus) {
  const call = await prisma.call.findUnique({ where: { id: callId }, select: { status: true } });
  emitToUsers(await getParticipantIds(callId), "callParticipantUpdate", {
    callId,
    userId,
    status,
    callStatus: call?.status,
  });
}

/** Moves an open call to a final status, once. Safe to call concurrently. */
async function finishCall(callId: string, roomName: string, status: CallStatus) {
  const result = await prisma.call.updateMany({
    where: { id: callId, status: { in: openCallStatuses } },
    data: { status, endedAt: new Date() },
  });
  if (!result.count) return false;

  const now = new Date();
  await prisma.callParticipant.updateMany({
    where: { callId, status: CallParticipantStatus.RINGING },
    data: { status: CallParticipantStatus.MISSED },
  });
  await prisma.callParticipant.updateMany({
    where: { callId, status: { in: inCallStatuses } },
    data: { status: CallParticipantStatus.LEFT, leftAt: now },
  });
  emitToUsers(await getParticipantIds(callId), "callEnded", { callId, status });

  // The call is already final, so a failure here only leaves an empty room behind
  // (LiveKit closes it on its own; a late join is refused by the webhook handler).
  await closeLiveKitRoomIfPresent(roomName).catch((error) =>
    logger.warn("Failed to close LiveKit room", { callId, error: error instanceof Error ? error.message : String(error) })
  );
  return true;
}

/**
 * Ends the call when it can no longer be a conversation: fewer than two people
 * in it and nobody left to ring. Called after every change that removes someone.
 */
async function settleCall(callId: string) {
  const call = await prisma.call.findUnique({
    where: { id: callId },
    select: { id: true, status: true, roomName: true, participants: { select: { status: true } } },
  });
  if (!call || isTerminal(call.status)) return;

  const inCall = call.participants.filter((p) => inCallStatuses.includes(p.status)).length;
  const ringing = call.participants.filter((p) => p.status === CallParticipantStatus.RINGING).length;
  if (inCall >= 2 || (inCall === 1 && ringing > 0)) return;

  let status: CallStatus = CallStatus.ENDED;
  if (call.status === CallStatus.RINGING) {
    if (inCall === 0) status = CallStatus.CANCELLED;
    else if (call.participants.some((p) => p.status === CallParticipantStatus.MISSED)) status = CallStatus.MISSED;
    else status = CallStatus.REJECTED;
  }
  await finishCall(call.id, call.roomName, status);
}

export async function startCall(convoId: string, userId: string, type: CallType = CallType.AUDIO) {
  if (!convoId) throw new apiError(400, "conversationId is required");
  if (!Object.values(CallType).includes(type)) throw new apiError(400, "type must be AUDIO or VIDEO");

  const conversation = await prisma.conversation.findUnique({
    where: { id: convoId },
    select: { id: true, type: true, participants: { select: { userId: true } } },
  });
  if (!conversation) throw new apiError(404, "Conversation not found");
  if (!conversation.participants.some((participant) => participant.userId === userId)) {
    throw new apiError(403, "You are not a participant of this conversation");
  }
  if (conversation.participants.length < 2) throw new apiError(400, "Calls require at least two conversation participants");

  const isGroup = conversation.type === "group";
  const inviteeIds = conversation.participants.map((p) => p.userId).filter((id) => id !== userId);

  if (!isGroup) {
    const block = await prisma.userBlock.findFirst({
      where: {
        OR: [
          { blockerId: userId, blockedId: { in: inviteeIds } },
          { blockerId: { in: inviteeIds }, blockedId: userId },
        ],
      },
      select: { blockerId: true },
    });
    if (block) throw new apiError(403, "You can't call this person");
  }

  // One call per conversation: if one is already ringing or in progress, the
  // client joins it instead (also settles both sides calling each other at once).
  const openCall = await prisma.call.findFirst({
    where: { convoId, status: { in: openCallStatuses } },
    orderBy: { createdAt: "desc" },
    include: { participants: { select: { userId: true, status: true } } },
  });
  if (openCall) return { ...openCall, isGroup, existing: true };

  // Invitees already in another open call are marked busy instead of rung.
  const busyRows = await prisma.callParticipant.findMany({
    where: {
      userId: { in: inviteeIds },
      status: { in: inCallStatuses },
      call: { status: { in: openCallStatuses } },
    },
    select: { userId: true },
  });
  const busyIds = new Set(busyRows.map((row) => row.userId));

  const callId = randomUUID();
  const roomName = `conversation-${convoId}-call-${callId}`;
  const call = await prisma.call.create({
    data: {
      id: callId,
      convoId,
      roomName,
      type,
      initiatedBy: userId,
      participants: {
        create: conversation.participants.map(({ userId: participantId }) => ({
          userId: participantId,
          status: participantId === userId
            ? CallParticipantStatus.ACCEPTED
            : busyIds.has(participantId)
              ? CallParticipantStatus.BUSY
              : CallParticipantStatus.RINGING,
        })),
      },
    },
    include: { participants: { select: { userId: true, status: true } } },
  });

  const ringingIds = call.participants
    .filter((participant) => participant.status === CallParticipantStatus.RINGING)
    .map((participant) => participant.userId);
  const summary = { callId: call.id, conversationId: call.convoId, type: call.type, isGroup, createdAt: call.createdAt };

  if (ringingIds.length === 0) {
    // Everyone is busy: nothing to ring.
    await finishCall(call.id, call.roomName, CallStatus.REJECTED);
    return { ...call, status: CallStatus.REJECTED, isGroup, existing: false };
  }

  emitToUsers(ringingIds, "callIncoming", { ...summary, initiatedBy: userId });
  emitToUsers([userId], "callRinging", summary);
  return { ...call, isGroup, existing: false };
}

/** Accepts (or rejoins) a call for this user. Returns true if their status changed. */
async function admitToCall(
  call: { id: string; convoId: string; status: CallStatus; initiatedBy: string },
  userId: string,
  currentStatus: CallParticipantStatus | undefined
) {
  if (currentStatus && inCallStatuses.includes(currentStatus)) return false;

  if (currentStatus) {
    await prisma.callParticipant.update({
      where: { callId_userId: { callId: call.id, userId } },
      data: { status: CallParticipantStatus.ACCEPTED, leftAt: null },
    });
  } else {
    // Joined the group after the call started.
    await prisma.callParticipant.create({
      data: { callId: call.id, userId, status: CallParticipantStatus.ACCEPTED },
    });
  }

  if (userId !== call.initiatedBy && call.status === CallStatus.RINGING) {
    await prisma.call.updateMany({
      where: { id: call.id, status: CallStatus.RINGING },
      data: { status: CallStatus.ACTIVE, startedAt: new Date() },
    });
  }
  await emitParticipantUpdate(call.id, userId, CallParticipantStatus.ACCEPTED);
  return true;
}

async function loadOpenCallForMember(callId: string, userId: string) {
  const call = await prisma.call.findUnique({
    where: { id: callId },
    include: { participants: { where: { userId }, take: 1 } },
  });
  if (!call) throw new apiError(404, "Call not found");
  if (isTerminal(call.status)) throw new apiError(409, "Call has ended");

  const membership = await prisma.conversationParticipant.findUnique({
    where: { convoId_userId: { convoId: call.convoId, userId } },
    select: { userId: true },
  });
  if (!membership) throw new apiError(403, "You are not a participant of this conversation");
  return { call, participant: call.participants[0] };
}

async function getDisplayName(userId: string) {
  const user = await prisma.user.findUnique({ where: { id: userId }, select: { name: true, lname: true } });
  return user ? `${user.name ?? ""} ${user.lname ?? ""}`.trim() || undefined : undefined;
}

/**
 * Answers a ringing call, rejoins one you left or missed (group calls), or
 * reconnects, and returns LiveKit credentials. One round trip for the client.
 */
export async function joinCall(callId: string, userId: string) {
  const { call, participant } = await loadOpenCallForMember(callId, userId);
  await admitToCall(call, userId, participant?.status);

  const credentials = await createParticipantToken(userId, call.roomName, await getDisplayName(userId));
  const latest = await prisma.call.findUnique({ where: { id: callId }, select: { status: true } });
  return {
    ...credentials,
    callId: call.id,
    conversationId: call.convoId,
    type: call.type,
    status: latest?.status ?? call.status,
  };
}

/** Token for someone who has already accepted (e.g. reconnecting). */
export async function createCallParticipantToken(callId: string, userId: string) {
  const { call, participant } = await loadOpenCallForMember(callId, userId);
  const joinableStatuses: CallParticipantStatus[] = [
    CallParticipantStatus.ACCEPTED,
    CallParticipantStatus.JOINED,
    CallParticipantStatus.LEFT,
  ];
  if (!participant || !joinableStatuses.includes(participant.status)) {
    throw new apiError(403, "Accept the call before joining");
  }

  const credentials = await createParticipantToken(userId, call.roomName, await getDisplayName(userId));
  return { ...credentials, callId: call.id };
}

export async function respondToCall(
  callId: string,
  userId: string,
  response: "accept" | "reject" | "busy"
) {
  const call = await prisma.call.findUnique({
    where: { id: callId },
    include: { participants: { where: { userId }, take: 1 } },
  });
  if (!call) throw new apiError(404, "Call not found");
  const participant = call.participants[0];
  if (!participant) throw new apiError(403, "You are not a participant of this call");
  if (isTerminal(call.status) || participant.status !== CallParticipantStatus.RINGING) {
    throw new apiError(409, "Call response is not valid in the current state");
  }

  if (response === "accept") {
    await admitToCall(call, userId, participant.status);
    return { callId, userId, status: CallParticipantStatus.ACCEPTED };
  }

  const nextStatus = response === "busy" ? CallParticipantStatus.BUSY : CallParticipantStatus.REJECTED;
  const result = await prisma.callParticipant.updateMany({
    where: { callId, userId, status: CallParticipantStatus.RINGING },
    data: { status: nextStatus },
  });
  if (!result.count) throw new apiError(409, "Call response is not valid in the current state");

  await emitParticipantUpdate(callId, userId, nextStatus);
  await settleCall(callId);
  return { callId, userId, status: nextStatus };
}

/** Hang up: leaves the call; the call ends by itself once nobody is left to talk to. */
export async function leaveCall(callId: string, userId: string) {
  const call = await prisma.call.findUnique({
    where: { id: callId },
    include: { participants: { where: { userId }, take: 1 } },
  });
  if (!call) throw new apiError(404, "Call not found");
  const participant = call.participants[0];
  if (!participant) throw new apiError(403, "You are not a participant of this call");
  if (isTerminal(call.status)) return { callId, status: call.status };

  if (inCallStatuses.includes(participant.status) || participant.status === CallParticipantStatus.RINGING) {
    const nextStatus = participant.status === CallParticipantStatus.RINGING
      ? CallParticipantStatus.REJECTED
      : CallParticipantStatus.LEFT;
    await prisma.callParticipant.updateMany({
      where: { callId, userId, status: participant.status },
      data: { status: nextStatus, ...(nextStatus === CallParticipantStatus.LEFT && { leftAt: new Date() }) },
    });
    await emitParticipantUpdate(callId, userId, nextStatus);
  }
  await settleCall(callId);

  const latest = await prisma.call.findUnique({ where: { id: callId }, select: { status: true } });
  return { callId, status: latest?.status ?? call.status };
}

export async function cancelCall(callId: string, userId: string) {
  const call = await prisma.call.findUnique({ where: { id: callId } });
  if (!call) throw new apiError(404, "Call not found");
  if (call.initiatedBy !== userId) throw new apiError(403, "Only the caller can cancel this call");
  if (call.status === CallStatus.CANCELLED) return { callId, status: CallStatus.CANCELLED };
  if (call.status !== CallStatus.RINGING) throw new apiError(409, "Only a ringing call can be cancelled");

  const cancelled = await finishCall(callId, call.roomName, CallStatus.CANCELLED);
  if (!cancelled) {
    const latest = await prisma.call.findUnique({ where: { id: callId }, select: { status: true } });
    if (latest?.status !== CallStatus.CANCELLED) throw new apiError(409, "Only a ringing call can be cancelled");
  }
  return { callId, status: CallStatus.CANCELLED };
}

/** Ends the call for everyone: anyone in a 1:1 call, or the caller in a group call. */
export async function endCall(callId: string, userId: string) {
  const call = await prisma.call.findUnique({
    where: { id: callId },
    include: {
      conversation: { select: { type: true } },
      participants: { where: { userId }, take: 1 },
    },
  });
  if (!call) throw new apiError(404, "Call not found");
  const participant = call.participants[0];
  if (!participant) throw new apiError(403, "You are not a participant of this call");
  if (call.status === CallStatus.ENDED) return { callId, status: CallStatus.ENDED };
  if (call.status !== CallStatus.ACTIVE) throw new apiError(409, "Only an active call can be ended");
  if (!inCallStatuses.includes(participant.status)) {
    throw new apiError(403, "Only a participant currently in the call can end it");
  }
  if (call.conversation.type === "group" && call.initiatedBy !== userId) {
    throw new apiError(403, "Only the caller can end a group call for everyone");
  }

  await finishCall(callId, call.roomName, CallStatus.ENDED);
  return { callId, status: CallStatus.ENDED };
}

/**
 * Calls the user should see right now: ringing for them, one they are in, or a
 * group call in progress that they can (re)join.
 */
export async function getOpenCallsForUser(userId: string) {
  const cutoff = new Date(Date.now() - RING_TIMEOUT_MS);
  const rows = await prisma.callParticipant.findMany({
    where: {
      userId,
      call: { status: { in: openCallStatuses } },
      OR: [
        { status: CallParticipantStatus.RINGING, call: { createdAt: { gte: cutoff } } },
        { status: { in: inCallStatuses } },
        { call: { status: CallStatus.ACTIVE, conversation: { type: "group" } } },
      ],
    },
    select: {
      status: true,
      call: {
        select: {
          id: true,
          convoId: true,
          type: true,
          status: true,
          initiatedBy: true,
          createdAt: true,
          conversation: { select: { type: true } },
        },
      },
    },
  });
  return rows.map(({ status, call }) => ({
    callId: call.id,
    conversationId: call.convoId,
    type: call.type,
    status: call.status,
    initiatedBy: call.initiatedBy,
    isGroup: call.conversation.type === "group",
    createdAt: call.createdAt,
    myStatus: status,
  }));
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
      type: true,
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
  const userId = event.participant?.identity;

  if (event.event === "participant_joined" && userId) {
    if (isTerminal(call.status)) {
      await closeLiveKitRoomIfPresent(roomName);
      return;
    }
    const joined = await prisma.callParticipant.updateMany({
      where: {
        callId: call.id,
        userId,
        status: { in: [CallParticipantStatus.ACCEPTED, CallParticipantStatus.LEFT] },
      },
      data: { status: CallParticipantStatus.JOINED, joinedAt: new Date(), leftAt: null },
    });
    if (joined.count) await emitParticipantUpdate(call.id, userId, CallParticipantStatus.JOINED);
  } else if (event.event === "participant_left" && userId) {
    const left = await prisma.callParticipant.updateMany({
      where: { callId: call.id, userId, status: { in: inCallStatuses } },
      data: { status: CallParticipantStatus.LEFT, leftAt: new Date() },
    });
    if (left.count) {
      await emitParticipantUpdate(call.id, userId, CallParticipantStatus.LEFT);
      await settleCall(call.id);
    }
  } else if (event.event === "room_finished" && !isTerminal(call.status)) {
    await finishCall(
      call.id,
      roomName,
      call.status === CallStatus.RINGING ? CallStatus.MISSED : CallStatus.ENDED
    );
  }
}

/** Stops ringing people who have not answered within RING_TIMEOUT_MS. */
export async function markTimedOutCallsMissed() {
  const cutoff = new Date(Date.now() - RING_TIMEOUT_MS);
  const calls = await prisma.call.findMany({
    where: {
      status: { in: openCallStatuses },
      createdAt: { lt: cutoff },
      participants: { some: { status: CallParticipantStatus.RINGING } },
    },
    select: { id: true, participants: { where: { status: CallParticipantStatus.RINGING }, select: { userId: true } } },
    take: 100,
  });

  for (const call of calls) {
    const missed = await prisma.callParticipant.updateMany({
      where: { callId: call.id, status: CallParticipantStatus.RINGING },
      data: { status: CallParticipantStatus.MISSED },
    });
    if (!missed.count) continue;
    for (const { userId } of call.participants) {
      await emitParticipantUpdate(call.id, userId, CallParticipantStatus.MISSED);
    }
    await settleCall(call.id);
  }
}

/**
 * Ends answered calls whose LiveKit room has been empty past the grace period:
 * covers closed tabs and lost networks when webhooks are not delivered.
 */
export async function endAbandonedCalls() {
  const calls = await prisma.call.findMany({
    where: { status: CallStatus.ACTIVE, startedAt: { lt: new Date(Date.now() - EMPTY_ROOM_GRACE_MS) } },
    select: { id: true, roomName: true },
    take: 100,
  });
  if (calls.length === 0) return;

  const occupancy = await getRoomOccupancy(calls.map((call) => call.roomName));
  for (const call of calls) {
    if (!occupancy.get(call.roomName)) {
      await finishCall(call.id, call.roomName, CallStatus.ENDED);
    }
  }
}

export function startCallTimeoutWorker() {
  let running = false;
  const run = async () => {
    if (running) return;
    running = true;
    try {
      await markTimedOutCallsMissed();
      await endAbandonedCalls();
    } catch (error) {
      logger.error("Call sweep failed", { error: error instanceof Error ? error.message : String(error) });
    } finally {
      running = false;
    }
  };
  const timer = setInterval(() => void run(), SWEEP_INTERVAL_MS);
  timer.unref();
}
