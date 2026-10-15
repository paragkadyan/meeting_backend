import { Socket } from "socket.io";
import { cancelCall, endCall, respondToCall } from "../services/call.service";
import { apiError } from "../utils/apiError";

type CallSocketEvent = "callAccept" | "callReject" | "callBusy" | "callCancel" | "callEnd";

export const handleCallEvents = (socket: Socket) => {
  const userId = socket.data.user.id as string;
  const handlers: Array<[CallSocketEvent, (callId: string) => Promise<unknown>]> = [
    ["callAccept", (callId) => respondToCall(callId, userId, "accept")],
    ["callReject", (callId) => respondToCall(callId, userId, "reject")],
    ["callBusy", (callId) => respondToCall(callId, userId, "busy")],
    ["callCancel", (callId) => cancelCall(callId, userId)],
    ["callEnd", (callId) => endCall(callId, userId)],
  ];

  for (const [event, handler] of handlers) {
    socket.on(event, async (payload: { callId?: unknown } = {}) => {
      if (typeof payload.callId !== "string" || !payload.callId) {
        socket.emit("callError", { event, message: "callId is required" });
        return;
      }
      try {
        await handler(payload.callId);
      } catch (error) {
        socket.emit("callError", {
          event,
          callId: payload.callId,
          message: error instanceof apiError ? error.message : "Call action failed",
        });
      }
    });
  }
};
