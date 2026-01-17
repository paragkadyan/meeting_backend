import { CorsOptions } from 'cors';
import { FRONTEND_ORIGIN } from './env';


const allowedOrigins = [
    "https://heyllow.netlify.app",
    "https://preview--sleek-commune.lovable.app",
    "http://localhost:8080"
];

export const corsOptions: CorsOptions = {
    origin: allowedOrigins,
    credentials: true,
};