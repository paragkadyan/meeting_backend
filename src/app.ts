import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import { corsOptions } from './config/cors';
import routes from './routes';
import { errorHandler } from './middleware/error.middleware';

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors(corsOptions));

app.use('/auth', routes.auth);
app.use('/', routes.index);

app.use(errorHandler);


export default app;


