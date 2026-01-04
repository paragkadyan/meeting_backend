import { Router } from 'express';
import { authMiddleware } from '../middleware/auth.middleware';
import { createDirectChat, getConversations, getMessages, getUsersBatch } from '../controllers/chat.controller';


const router = Router();


router.route('/create-direct-chat').post(
    authMiddleware, createDirectChat
);

router.route('/get-conversations').get(
    authMiddleware, getConversations
);

router.route('/get-users-batch').post(
    authMiddleware, getUsersBatch
);

router.route('/get-messages').get(
    authMiddleware, getMessages
);


export default router;