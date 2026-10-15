import { Router } from "express";
import { authMiddleware } from "../middleware/auth.middleware";
import {
  acceptCallController,
  busyCallController,
  callHistoryController,
  callTokenController,
  cancelCallController,
  endCallController,
  rejectCallController,
  startCallController,
} from "../controllers/call.controller";

const router = Router();

router.use(authMiddleware);
router.get("/", callHistoryController);
router.post("/", startCallController);
router.post("/:callId/token", callTokenController);
router.post("/:callId/accept", acceptCallController);
router.post("/:callId/reject", rejectCallController);
router.post("/:callId/busy", busyCallController);
router.post("/:callId/cancel", cancelCallController);
router.post("/:callId/end", endCallController);

export default router;
