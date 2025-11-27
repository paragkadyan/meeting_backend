import dotenv from 'dotenv';
dotenv.config();


export const DATABASE_URL = process.env.DATABASE_URL;
export const CASSANDRA_HOST = process.env.CASSANDRA_HOST;
export const CASSANDRA_DATACENTER = process.env.CASSANDRA_DATACENTER;
export const CASSANDRA_KEYSPACE = process.env.CASSANDRA_KEYSPACE;
export const REDIS_HOST = process.env.REDIS_HOST;
export const REDIS_PORT = Number(process.env.REDIS_PORT);
export const PORT = Number(process.env.PORT);
export const NODE_ENV = process.env.NODE_ENV;
export const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET;
export const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET;
export const ACCESS_TOKEN_EXPIRES_IN = process.env.ACCESS_TOKEN_EXPIRES_IN;
export const REFRESH_TOKEN_EXPIRES_IN = process.env.REFRESH_TOKEN_EXPIRES_IN;
export const COOKIE_DOMAIN = process.env.COOKIE_DOMAIN;
export const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN;
export const COOKIE_SECURE = NODE_ENV === 'production';
