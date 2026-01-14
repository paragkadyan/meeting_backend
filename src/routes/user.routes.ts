import { Router } from 'express';
import { authMiddleware } from '../middleware/auth.middleware';
import { createDirectChat, createGroupChat, getConversations, getMessages, getOlderMessages, getUsersBatch, groupLeaveByUser, groupUpdate, userLastSeen, } from '../controllers/chat.controller';


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

router.route('/last-seen').get(
    authMiddleware, userLastSeen
);

router.route(`/get-older-messages`).post(
    authMiddleware, getOlderMessages
);

router.route('/group-update').post(
    authMiddleware, groupUpdate
);

router.route('/group-leave').post(
    authMiddleware, groupLeaveByUser
);
export default router;