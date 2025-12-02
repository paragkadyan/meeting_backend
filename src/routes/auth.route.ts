import { Router } from 'express';
import {forgotPassword, login, signup, verifyResetOtp, resetPassword} from '../controllers/auth.controller';


const router = Router();


router.route("/signup").post(
    signup
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

export default router;