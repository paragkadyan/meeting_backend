import { Request, Response } from "express";
import { WebhookReceiver } from "livekit-server-sdk";
import { getLiveKitWebhookCredentials } from "../services/livekit.service";
import { handleLiveKitWebhook } from "../services/call.service";
import { apiError } from "../utils/apiError";

export async function livekitWebhookController(req: Request, res: Response) {
  if (!Buffer.isBuffer(req.body)) throw new apiError(400, "Expected raw LiveKit webhook body");
  const { apiKey, apiSecret } = getLiveKitWebhookCredentials();
  const receiver = new WebhookReceiver(apiKey, apiSecret);
  let event;
  try {
    event = await receiver.receive(req.body.toString("utf8"), req.get("Authorization"));
  } catch (error) {
    return res.status(401).json({ success: false, message: "Invalid LiveKit webhook" });
  }
  await handleLiveKitWebhook(event);
  res.status(200).json({ success: true });
}
