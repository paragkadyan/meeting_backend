import { AccessToken, RoomServiceClient } from "livekit-server-sdk";
import { LIVEKIT_API_KEY, LIVEKIT_API_SECRET, LIVEKIT_PUBLIC_URL, LIVEKIT_URL } from "../config/env";
import { apiError } from "../utils/apiError";

function getLiveKitConfig() {
  if (!LIVEKIT_URL) throw new apiError(503, "LiveKit URL is not configured");
  if (!LIVEKIT_API_KEY) throw new apiError(503, "LiveKit API key is not configured");
  if (!LIVEKIT_API_SECRET) throw new apiError(503, "LiveKit API secret is not configured");
  return { url: LIVEKIT_URL, apiKey: LIVEKIT_API_KEY, apiSecret: LIVEKIT_API_SECRET };
}

// One client for the process; it is stateless apart from its credentials.
let roomService: RoomServiceClient | null = null;
function getRoomService() {
  if (!roomService) {
    const config = getLiveKitConfig();
    const httpUrl = config.url.replace(/^wss:/i, "https:").replace(/^ws:/i, "http:");
    roomService = new RoomServiceClient(httpUrl, config.apiKey, config.apiSecret);
  }
  return roomService;
}

const isNotFound = (error: unknown) => {
  const { status, code } = (error ?? {}) as { status?: number; code?: string };
  return status === 404 || code === "not_found";
};

export async function createParticipantToken(userId: string, roomName: string, displayName?: string) {
  const config = getLiveKitConfig();
  const token = new AccessToken(config.apiKey, config.apiSecret, {
    identity: userId,
    name: displayName,
    // Only needs to outlive the initial connect; LiveKit refreshes it for the session.
    ttl: "2m",
  });
  token.addGrant({
    roomJoin: true,
    room: roomName,
    canPublish: true,
    canSubscribe: true,
    canPublishData: false,
  });

  // The server's own LIVEKIT_URL may be a Docker/internal address; clients get the public one.
  return { token: await token.toJwt(), serverUrl: LIVEKIT_PUBLIC_URL || config.url };
}

export function getLiveKitWebhookCredentials() {
  return getLiveKitConfig();
}

export async function closeLiveKitRoomIfPresent(roomName: string) {
  try {
    await getRoomService().deleteRoom(roomName);
  } catch (error) {
    if (!isNotFound(error)) throw error;
  }
}

/** Participant counts for the given rooms that currently exist on LiveKit (one API call). */
export async function getRoomOccupancy(roomNames: string[]): Promise<Map<string, number>> {
  if (roomNames.length === 0) return new Map();
  const rooms = await getRoomService().listRooms(roomNames);
  return new Map(rooms.map((room) => [room.name, room.numParticipants]));
}

/** Whether this user is connected to the room right now. */
export async function isUserInRoom(roomName: string, userId: string): Promise<boolean> {
  try {
    const participants = await getRoomService().listParticipants(roomName);
    return participants.some((participant) => participant.identity === userId);
  } catch (error) {
    if (isNotFound(error)) return false;
    throw error;
  }
}
