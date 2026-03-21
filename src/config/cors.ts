import { CorsOptions } from 'cors';
import { FRONTEND_ORIGIN } from './env';


const allowedOrigins = FRONTEND_ORIGIN;

export const corsOptions: CorsOptions = {
    origin: allowedOrigins,
    credentials: true,
};