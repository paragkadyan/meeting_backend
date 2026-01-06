import { Router } from 'express';
import { authMiddleware } from '../middleware/auth.middleware';
import { createDirectChat, createGroupChat, getConversations, getMessages, getUsersBatch } from '../controllers/chat.controller';


const router = Router();


router.route('/create-direct-chat').post(
    authMiddleware, createDirectChat
);

router.route('/create-group-chat').post(
    authMiddleware, createGroupChat
);

router.route('/get-conversations').get(
    authMiddleware, getConversations
);

router.route('/get-users-batch').post(
    authMiddleware, getUsersBatch
);

router.route('/get-messages').post(
    authMiddleware, getMessages
);


export default router;