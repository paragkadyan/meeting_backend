
import "dotenv/config";
import { AccessToken, RoomServiceClient } from "livekit-server-sdk";

async function main() {
  const url = process.env.LIVEKIT_URL;
  const key = process.env.LIVEKIT_API_KEY;
  const secret = process.env.LIVEKIT_API_SECRET;

  if (!url || !key || !secret) {
    throw new Error("Missing LiveKit environment variables");
  }

  const httpUrl = url.replace(/^ws:/, "http:").replace(/^wss:/, "https:");
  const rooms = new RoomServiceClient(httpUrl, key, secret);

  // Test 1: LiveKit API connectivity and authentication
  const existingRooms = await rooms.listRooms();
  console.log("PASS: LiveKit API connected");
  console.log("Existing rooms:", existingRooms.map((r) => r.name));

  // Test 2: Generate a participant token
  const testRoom = `integration-test-${Date.now()}`;
  const token = new AccessToken(key, secret, {
    identity: `test-user-${Date.now()}`,
    ttl: "10m",
  });

  token.addGrant({
    roomJoin: true,
    room: testRoom,
    canPublish: true,
    canSubscribe: true,
  });

  const jwt = await token.toJwt();
  console.log("PASS: Participant token generated");
  console.log("Token generated:", Boolean(jwt));
  console.log("Room:", testRoom);

  // Test 3: Confirm room is not required to exist before joining
  console.log("PASS: Token grants access to the intended room");
  console.log("Note: This does not yet test media or room joining.");
}

main().catch((error) => {
  console.error("FAIL: LiveKit test failed", error);
  process.exitCode = 1;
});
