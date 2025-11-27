import { Router } from 'express';
import authRouter from './auth.route';
import userRouter from './user.routes';


const router = Router();
router.use('/auth', authRouter);
router.use('/user', userRouter);


export default { auth: authRouter, index: router };