import { Router } from 'express';
import { forgotPassword, login, signup, verifyResetOtp, resetPassword, verifySignupOTP, deleteAccount, editProfile, resendSignupOTP, logout, changePassword, cloudinarySignature, getProfile, loginWithGoogle, searchUser, inviteUser, feedback } from '../controllers/user.controller';
import { authMiddleware } from '../middleware/auth.middleware';

const router = Router();


router.route("/signup").post(
    signup
)

router.route("/verifySignupOtp").post(
    verifySignupOTP
)

router.route("/resendSignupOtp").post(
    resendSignupOTP
)

router.route("/login").post(
    login
)

router.route("/forgotPassword").post(
    forgotPassword
)

router.route("/verifyResetOtp").post(
    verifyResetOtp
)

router.route("/resetPassword").post(
    resetPassword
)

router.route("/logout").post(
    authMiddleware, logout
)

router.route("/changePassword").put(
    authMiddleware, changePassword
)

router.route("/editProfile").put(
    authMiddleware, editProfile
)

router.route("/deleteAccount").delete(
    authMiddleware, deleteAccount
)

router.route("/cloudinarySignature").get(
    authMiddleware, cloudinarySignature
)

router.route("/user/profile").get(
    authMiddleware, getProfile
)

router.route("/google").post(
    loginWithGoogle
)

router.route('/me').get(
    authMiddleware, getProfile
);

router.route('/search-user').post(
    authMiddleware, searchUser
);

router.route('/invite-user').post(
    authMiddleware, inviteUser
);

router.route('/user-feedback').post(
    authMiddleware, feedback
);


export default router;