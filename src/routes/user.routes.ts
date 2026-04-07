import { Router } from 'express';
import { authMiddleware } from '../middleware/auth.middleware';
import { addNewUsersToGroup, assignAdminRole, createDirectChat, createGroupChat, getConversations, getMessageReadReceipts, getMessages, getOlderMessages, getUsersBatch, groupLeaveByUser, groupUpdate, kickUserFromGroup, lastReadMessageByUser, userLastSeen, } from '../controllers/chat.controller';
import { blockUser, unblockUser } from '../controllers/user.controller';


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

router.route('/last-seen').post(
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

router.route('/add-member-to-group').post(
    authMiddleware, addNewUsersToGroup
);

router.route('/remove-member-from-group').post(
    authMiddleware, kickUserFromGroup
);

router.route('/message-read-receipts').post(
    authMiddleware, getMessageReadReceipts
);

router.route('/last-read-message').post(
    authMiddleware, lastReadMessageByUser
);

router.route('/assign-admin').post(
    authMiddleware, assignAdminRole
);

router.route('/remove-admin').post(
    authMiddleware, assignAdminRole
);

router.route('/block-user').post(
    authMiddleware, blockUser
);

router.route('/unblock-user').post(
    authMiddleware, unblockUser
);

export default router;