import { Router } from 'express';
import { authMiddleware } from '../middleware/auth.middleware';


const router = Router();


router.get('/profile', authMiddleware, (req, res) => {
    return res.json({ ok: true, userId: req.user?.id });
});


export default router;