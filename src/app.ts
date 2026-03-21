import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { corsOptions } from './config/cors';
import { errorHandler } from "./middleware/errorHandler.middleware";
import authRouter from "./routes/auth.route";
import userRouter from "./routes/user.routes";
import mediaRouter from "./media/routes/media.routes";
import { logger } from "./logger/logger";


const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors(corsOptions));
app.use((req, _res, next) => {
  logger.info("Incoming request", { method: req.method, path: req.path });
  next();
});

app.use("/api/auth", authRouter)

app.use("/api/user", userRouter)
app.use("/", mediaRouter);

app.use(errorHandler);

export default app;

