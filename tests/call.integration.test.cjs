const assert = require("node:assert/strict");
const Module = require("node:module");
const path = require("node:path");
const { test } = require("node:test");

process.env.LIVEKIT_URL = "ws://localhost:7880";
process.env.LIVEKIT_API_KEY = "devkey";
process.env.LIVEKIT_API_SECRET = "devsecret-for-tests-only";
process.env.JWT_ACCESS_SECRET = "access-secret-for-tests-only";

const fakePrisma = {};
const emitted = [];
const closedRooms = [];
const postedMessages = [];
const callPushes = [];
function setFakePrisma(next) {
  for (const key of Object.keys(fakePrisma)) delete fakePrisma[key];
  Object.assign(fakePrisma, next);
}
const originalLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (parent && path.basename(parent.filename) === "call.service.js") {
    if (request === "../db/post") return { prisma: fakePrisma };
    if (request === "../socket") {
      return {
        getIO: () => ({
          to: (room) => ({ emit: (event, payload) => emitted.push({ room, event, payload }) }),
        }),
      };
    }
    if (request === "./pushNotification.service") {
      return { pushNotificationService: { sendIncomingCallNotification: async (userId, call) => { callPushes.push({ userId, call }); } } };
    }
    if (request === "./message.service") {
      return { createAndDeliverMessage: async (_io, message, options) => { postedMessages.push({ message, options }); return message; } };
    }
    if (request === "./livekit.service") {
      const real = originalLoad.call(this, request, parent, isMain);
      return { ...real, closeLiveKitRoomIfPresent: async (roomName) => { closedRooms.push(roomName); } };
    }
  }
  return originalLoad.call(this, request, parent, isMain);
};

const callService = require("../dist/src/services/call.service.js");
const { TokenVerifier } = require("livekit-server-sdk");
const jwt = require("jsonwebtoken");
const { authMiddleware } = require("../dist/src/middleware/auth.middleware.js");

function authenticate(req) {
  return new Promise((resolve, reject) => {
    authMiddleware(req, {}, (error) => error ? reject(error) : resolve(req.user));
  });
}

test("conversation member can start a call and notifications omit the room name", async () => {
  emitted.length = 0;
  setFakePrisma({
    conversation: {
      findUnique: async () => ({
        id: "conversation-1",
        type: "direct",
        participants: [{ userId: "user-1" }, { userId: "user-2" }],
      }),
    },
    userBlock: { findFirst: async () => null },
    call: {
      findFirst: async () => null,
      create: async ({ data }) => ({
        id: data.id,
        convoId: data.convoId,
        roomName: data.roomName,
        status: data.status || "RINGING",
        createdAt: new Date("2026-10-05T00:00:00Z"),
        participants: data.participants.create,
      }),
    },
    callParticipant: {
      findMany: async ({ where }) =>
        where.callId ? [{ userId: "user-1" }, { userId: "user-2" }] : [],
    },
  });

  const call = await callService.startCall("conversation-1", "user-1");
  assert.equal(call.convoId, "conversation-1");
  assert.match(call.roomName, /^conversation-conversation-1-call-/);
  assert.equal(call.participants.find((participant) => participant.userId === "user-1").status, "ACCEPTED");
  assert.equal(emitted.some(({ event }) => event === "callIncoming"), true);
  assert.equal(emitted.every(({ payload }) => !("roomName" in payload)), true);
  // The person rung also gets a push (for a phone with the app in the background); the caller doesn't.
  assert.deepEqual(callPushes.map(({ userId }) => userId), ["user-2"]);
});

test("conversation non-member cannot create a call", async () => {
  setFakePrisma({
    conversation: {
      findUnique: async () => ({ id: "conversation-1", participants: [{ userId: "user-2" }] }),
    },
    call: { create: async () => assert.fail("call must not be created") },
  });
  await assert.rejects(callService.startCall("conversation-1", "outsider"), (error) => error.statusCode === 403);
});

test("existing access-token auth rejects anonymous requests and accepts authenticated users", async () => {
  await assert.rejects(authenticate({ cookies: {} }), (error) => error.statusCode === 401);
  const accessToken = jwt.sign({ userId: "user-1" }, process.env.JWT_ACCESS_SECRET);
  assert.deepEqual(await authenticate({ cookies: { accessToken } }), { id: "user-1" });
});

test("call responses in an invalid state are rejected", async () => {
  setFakePrisma({
    call: {
      findUnique: async () => ({
        id: "call-1",
        status: "ENDED",
        participants: [{ status: "RINGING" }],
      }),
    },
  });
  await assert.rejects(callService.respondToCall("call-1", "user-2", "accept"), (error) => error.statusCode === 409);
});

test("LiveKit token is signed for the server-authenticated identity and scoped room", async () => {
  setFakePrisma({
    call: {
      findUnique: async () => ({
        id: "call-1",
        convoId: "conversation-1",
        roomName: "conversation-conversation-1-call-call-1",
        status: "RINGING",
        participants: [{ status: "ACCEPTED" }],
      }),
    },
    conversationParticipant: { findUnique: async () => ({ userId: "user-2" }) },
    user: { findUnique: async () => ({ name: "Second", lname: "User" }) },
  });

  const result = await callService.createCallParticipantToken("call-1", "user-2");
  const claims = await new TokenVerifier("devkey", "devsecret-for-tests-only").verify(result.token);
  assert.equal(claims.sub, "user-2");
  assert.equal(claims.video.room, "conversation-conversation-1-call-call-1");
  assert.equal(claims.video.roomJoin, true);
  assert.equal(claims.video.canPublish, true);
  assert.equal(claims.video.canSubscribe, true);
  assert.equal(claims.video.roomAdmin, undefined);
  assert.deepEqual(Object.keys(result).sort(), ["callId", "serverUrl", "token"]);
  assert.equal(JSON.stringify(result).includes("devsecret-for-tests-only"), false);
});

test("missing LiveKit settings fail token creation", async () => {
  const original = {
    url: process.env.LIVEKIT_URL,
    key: process.env.LIVEKIT_API_KEY,
    secret: process.env.LIVEKIT_API_SECRET,
  };
  const envModulePath = require.resolve("../dist/src/config/env.js");
  const serviceModulePath = require.resolve("../dist/src/services/livekit.service.js");
  try {
    for (const [name, value] of [
      ["LIVEKIT_URL", ""],
      ["LIVEKIT_API_KEY", ""],
      ["LIVEKIT_API_SECRET", ""],
    ]) {
      process.env.LIVEKIT_URL = original.url;
      process.env.LIVEKIT_API_KEY = original.key;
      process.env.LIVEKIT_API_SECRET = original.secret;
      process.env[name] = value;
      delete require.cache[serviceModulePath];
      delete require.cache[envModulePath];
      const freshService = require(serviceModulePath);
      await assert.rejects(freshService.createParticipantToken("user-1", "room-1"), (error) => error.statusCode === 503);
    }
  } finally {
    process.env.LIVEKIT_URL = original.url;
    process.env.LIVEKIT_API_KEY = original.key;
    process.env.LIVEKIT_API_SECRET = original.secret;
    delete require.cache[serviceModulePath];
    delete require.cache[envModulePath];
  }
});

// --- Call lifecycle, against a small in-memory stand-in for the call tables ---

const matches = (value, condition) =>
  condition === undefined ||
  (condition && typeof condition === "object" && Array.isArray(condition.in)
    ? condition.in.includes(value)
    : value === condition);

function useCallStore({ status = "RINGING", type = "direct", participants }) {
  const call = {
    id: "call-1",
    convoId: "conversation-1",
    roomName: "room-1",
    initiatedBy: "user-1",
    type: "AUDIO",
    status,
    createdAt: new Date(),
    startedAt: status === "ACTIVE" ? new Date(Date.now() - 151_000) : null,
    endedAt: null,
    conversation: { type, participants: participants.map(([userId]) => ({ userId })) },
  };
  const parts = participants.map(([userId, partStatus]) => ({ callId: "call-1", userId, status: partStatus }));
  const withParticipants = (args = {}) => {
    const where = (args.include || args.select || {}).participants?.where;
    return { ...call, participants: parts.filter((p) => matches(p.userId, where?.userId)) };
  };
  const partsWhere = (where) =>
    parts.filter((p) => matches(p.userId, where.userId) && matches(p.status, where.status));

  setFakePrisma({
    call: {
      findUnique: async (args) => withParticipants(args),
      updateMany: async ({ where, data }) => {
        if (!matches(call.status, where.status)) return { count: 0 };
        Object.assign(call, data);
        return { count: 1 };
      },
    },
    callParticipant: {
      findMany: async () => parts.map(({ userId }) => ({ userId })),
      updateMany: async ({ where, data }) => {
        const rows = partsWhere(where);
        rows.forEach((row) => Object.assign(row, data));
        return { count: rows.length };
      },
      update: async ({ where, data }) => Object.assign(parts.find((p) => p.userId === where.callId_userId.userId), data),
      create: async ({ data }) => { parts.push({ ...data }); return data; },
    },
    conversationParticipant: { findUnique: async () => ({ userId: "member" }) },
    user: { findUnique: async () => ({ name: "Test", lname: "User" }) },
  });
  emitted.length = 0;
  closedRooms.length = 0;
  postedMessages.length = 0;
  return { call, parts };
}

const events = (name) => emitted.filter(({ event }) => event === name);

test("hanging up a 1:1 call ends it for both people and closes the room", async () => {
  const { call } = useCallStore({ status: "ACTIVE", participants: [["user-1", "JOINED"], ["user-2", "JOINED"]] });
  await callService.leaveCall("call-1", "user-2");
  assert.equal(call.status, "ENDED");
  assert.deepEqual(events("callEnded").map(({ room }) => room).sort(), ["user:user-1", "user:user-2"]);
  assert.deepEqual(closedRooms, ["room-1"]);
});

test("one person leaving a group call keeps it going for the rest", async () => {
  const { call } = useCallStore({
    status: "ACTIVE",
    type: "group",
    participants: [["user-1", "JOINED"], ["user-2", "JOINED"], ["user-3", "JOINED"]],
  });
  await callService.leaveCall("call-1", "user-3");
  assert.equal(call.status, "ACTIVE");
  assert.equal(events("callEnded").length, 0);
  assert.equal(events("callParticipantUpdate").every(({ payload }) => payload.status === "LEFT"), true);
});

test("declining a 1:1 call stops the caller ringing", async () => {
  const { call } = useCallStore({ participants: [["user-1", "ACCEPTED"], ["user-2", "RINGING"]] });
  await callService.respondToCall("call-1", "user-2", "reject");
  assert.equal(call.status, "REJECTED");
  assert.equal(events("callEnded")[0].payload.status, "REJECTED");
});

test("the caller hanging up while it rings cancels the call", async () => {
  const { call, parts } = useCallStore({ participants: [["user-1", "ACCEPTED"], ["user-2", "RINGING"]] });
  await callService.leaveCall("call-1", "user-1");
  assert.equal(call.status, "CANCELLED");
  assert.equal(parts.find((p) => p.userId === "user-2").status, "MISSED");
});

test("a group member who missed the ring can still join the call in progress", async () => {
  const { call, parts } = useCallStore({
    status: "ACTIVE",
    type: "group",
    participants: [["user-1", "JOINED"], ["user-2", "JOINED"], ["user-3", "MISSED"]],
  });
  const result = await callService.joinCall("call-1", "user-3");
  assert.equal(parts.find((p) => p.userId === "user-3").status, "ACCEPTED");
  assert.equal(call.status, "ACTIVE");
  assert.equal(typeof result.token, "string");
  assert.equal(result.type, "AUDIO");
});

test("answering marks a ringing call active; the caller joining does not", async () => {
  const { call } = useCallStore({ participants: [["user-1", "ACCEPTED"], ["user-2", "RINGING"]] });
  await callService.joinCall("call-1", "user-1");
  assert.equal(call.status, "RINGING");
  await callService.joinCall("call-1", "user-2");
  assert.equal(call.status, "ACTIVE");
});

test("a finished call is added to the chat with its duration", async () => {
  useCallStore({ status: "ACTIVE", participants: [["user-1", "JOINED"], ["user-2", "JOINED"]] });
  await callService.leaveCall("call-1", "user-2");
  assert.equal(postedMessages.length, 1);
  const { message, options } = postedMessages[0];
  assert.equal(message.messageType, "call");
  assert.equal(message.senderId, "user-1");
  assert.match(message.content, /^📞 Voice call · 2:3[0-9]$/);
  const details = JSON.parse(message.systemType);
  assert.equal(details.status, "ENDED");
  assert.equal(details.callType, "AUDIO");
  assert.ok(details.duration >= 150);
  assert.deepEqual(options.unreadUserIds, []);
  assert.deepEqual(options.pushUserIds, []);
});

test("an unanswered call shows as missed and is unread for the person rung", async () => {
  useCallStore({ participants: [["user-1", "ACCEPTED"], ["user-2", "RINGING"]] });
  await callService.leaveCall("call-1", "user-1");
  const { message, options } = postedMessages[0];
  assert.equal(message.content, "📞 Missed voice call");
  assert.equal(JSON.parse(message.systemType).status, "CANCELLED");
  assert.deepEqual(options.unreadUserIds, ["user-2"]);
});

test("a declined call is recorded as declined, without an unread badge", async () => {
  useCallStore({ participants: [["user-1", "ACCEPTED"], ["user-2", "RINGING"]] });
  await callService.respondToCall("call-1", "user-2", "reject");
  const { message, options } = postedMessages[0];
  assert.equal(message.content, "📞 Declined voice call");
  assert.deepEqual(options.unreadUserIds, []);
});
