import { CorsOptions } from 'cors';
import { FRONTEND_ORIGIN } from './env';


export const corsOptions: CorsOptions = {
    origin: FRONTEND_ORIGIN,
    credentials: true,
};