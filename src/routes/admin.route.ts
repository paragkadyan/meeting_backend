import { Router } from 'express';
import { addUser, adminLogin, changeAdminPassword, getAllUsers, getfeedbacks } from '../controllers/admin.controller';
import { authMiddleware } from '../middleware/auth.middleware';

const router = Router();
router.post('/login', (req, res) => {
    adminLogin
});
router.get('/dashboard', authMiddleware, (req, res) => {
    res.status(200).json({ message: 'Admin dashboard' });
});

router.get('/users',authMiddleware, getAllUsers);
router.get('/feedbacks',authMiddleware, getfeedbacks);
router.post('/users',authMiddleware, addUser);
router.post('/change-password', authMiddleware, changeAdminPassword);


export default router;