import { Router } from 'express';
import { authMiddleware } from '../middleware/auth.middleware';
import { createDirectChat, getConversations } from '../controllers/chat.controller';


const router = Router();


router.route('/create-direct-chat').post(
    authMiddleware, createDirectChat
);

router.route('/get-conversations').get(
    authMiddleware, getConversations
);


export default router;