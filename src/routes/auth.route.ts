import { Router } from 'express';
import {forgotPassword, login, signup, verifyResetOtp, resetPassword, verifySignupOTP, deleteAccount, editProfile, resendSignupOTP, logout, changePassword} from '../controllers/auth.controller';


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
    logout
)

router.route("/changePassword").put(
    changePassword
)

router.route("/editProfile").put(
    editProfile
)

router.route("/deleteAccount").delete(
    deleteAccount
)

export default router;