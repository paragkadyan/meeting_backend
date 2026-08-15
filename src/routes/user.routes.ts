import { Router } from 'express';
import { authMiddleware } from '../middleware/auth.middleware';
import { addNewUsersToGroup, assignAdminRole, createDirectChat, createGroupChat, deleteChatForUser, getConversations, getMessageReadReceipts, getMessages, getMessagesAround, getNewerMessages, getOlderMessages, getUsersBatch, groupLeaveByUser, groupUpdate, kickUserFromGroup, lastReadMessageByUser, removeAdminRole, updateConversationPreferences, userLastSeen, } from '../controllers/chat.controller';
import { blockUser, unblockUser } from '../controllers/user.controller';
import { imageUploadMiddleware } from '../middleware/imageUpload.middleware';
import { deletePushSubscription, registerPushSubscription, updatePushSubscription } from '../controllers/pushSubscription.controller';


const router = Router();


router.route('/create-direct-chat').post(
    authMiddleware, createDirectChat
);

router.route('/create-group-chat').post(
    authMiddleware, imageUploadMiddleware.single("avatar"), createGroupChat
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

router.route('/get-newer-messages').post(
    authMiddleware, getNewerMessages
);

router.route('get-messages-around').post(
    authMiddleware, getMessagesAround
);

router.route('/group-update').post(
    authMiddleware, imageUploadMiddleware.single("avatar"), groupUpdate
);

router.route('/conversation-preferences').post(
    authMiddleware, updateConversationPreferences
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
    authMiddleware, removeAdminRole
);

router.route('/block-user').post(
    authMiddleware, blockUser
);

router.route('/unblock-user').post(
    authMiddleware, unblockUser
);

router.route('/push-subscriptions').post(
    authMiddleware, registerPushSubscription
);

router.route('/push-subscriptions/:subscriptionId').put(
    authMiddleware, updatePushSubscription
);

router.route('/push-subscriptions/:subscriptionId').delete(
    authMiddleware, deletePushSubscription
);

router.route('/delete-chat/:convoId').delete(
    authMiddleware, deleteChatForUser
);

export default router;
