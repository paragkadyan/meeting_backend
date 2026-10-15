import { AccessToken, RoomServiceClient } from "livekit-server-sdk";
import { LIVEKIT_API_KEY, LIVEKIT_API_SECRET, LIVEKIT_URL } from "../config/env";
import { apiError } from "../utils/apiError";

function getLiveKitConfig() {
  if (!LIVEKIT_URL) throw new apiError(503, "LiveKit URL is not configured");
  if (!LIVEKIT_API_KEY) throw new apiError(503, "LiveKit API key is not configured");
  if (!LIVEKIT_API_SECRET) throw new apiError(503, "LiveKit API secret is not configured");
  return { url: LIVEKIT_URL, apiKey: LIVEKIT_API_KEY, apiSecret: LIVEKIT_API_SECRET };
}

export async function createParticipantToken(userId: string, roomName: string) {
  const config = getLiveKitConfig();
  const token = new AccessToken(config.apiKey, config.apiSecret, {
    identity: userId,
    ttl: "2m",
  });
  token.addGrant({
    roomJoin: true,
    room: roomName,
    canPublish: true,
    canSubscribe: true,
    canPublishData: false,
  });

  return { token: await token.toJwt(), serverUrl: config.url };
}

export function getLiveKitWebhookCredentials() {
  return getLiveKitConfig();
}

export async function closeLiveKitRoomIfPresent(roomName: string) {
  const config = getLiveKitConfig();
  const httpUrl = config.url.replace(/^wss:/i, "https:").replace(/^ws:/i, "http:");
  const rooms = new RoomServiceClient(httpUrl, config.apiKey, config.apiSecret);
  const existingRooms = await rooms.listRooms([roomName]);
  if (existingRooms.some((room) => room.name === roomName)) await rooms.deleteRoom(roomName);
}
