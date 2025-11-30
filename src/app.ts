import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { corsOptions } from './config/cors';
import { errorHandler } from './middleware/error.middleware';

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors(corsOptions));

import authRouter from "./routes/auth.route";
app.use("/api/auth", authRouter)

app.use(errorHandler);




export default app;


