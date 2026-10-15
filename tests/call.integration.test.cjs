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
        participants: [{ userId: "user-1" }, { userId: "user-2" }],
      }),
    },
    call: {
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
        status: "ACTIVE",
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
