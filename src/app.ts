import path from "path";
import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { corsOptions } from './config/cors';
import { errorHandler } from "./middleware/errorHandler.middleware";
import authRouter from "./routes/auth.route";
import userRouter from "./routes/user.routes";
import adminRouter from "./routes/admin.route";
import mediaRouter from "./media/routes/media.routes";
import { logger } from "./logger/logger";
import callRouter from "./routes/call.routes";
import { livekitWebhookController } from "./controllers/livekitWebhook.controller";

const publicAssetPath = path.join(process.cwd(), 'public', 'assets');

const app = express();
// LiveKit signs the raw webhook body, so this route must run before express.json().
app.post(
  "/api/calls/livekit/webhook",
  express.raw({ type: "application/webhook+json" }),
  livekitWebhookController
);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors(corsOptions));
app.use("/assets", express.static(publicAssetPath));
app.use((req, _res, next) => {
  logger.info("Incoming request", { method: req.method, path: req.path });
  next();
});

app.use("/api/auth", authRouter)
app.use("/api/admin", adminRouter)
app.use("/api/user", userRouter)
app.use("/api", mediaRouter);
app.use("/api/calls", callRouter);

app.use(errorHandler);

export default app;

