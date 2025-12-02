import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { corsOptions } from './config/cors';
import { errorHandler } from "./middleware/errorHandler.middleware";
import authRouter from "./routes/auth.route";


const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors(corsOptions));

app.use("/api/auth", authRouter)



app.use(errorHandler);

export default app;


