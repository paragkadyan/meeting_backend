import { Router } from 'express';
import { addUser, adminDashboard, adminLogin, changeAdminPassword, createAdmin, getAllUsers, getfeedbacks } from '../controllers/admin.controller';
import { authMiddleware } from '../middleware/auth.middleware';

const router = Router();
router.post('/login', adminLogin);
router.get('/dashboard', authMiddleware, adminDashboard);

router.get('/users', authMiddleware, getAllUsers);
router.get('/feedbacks', authMiddleware, getfeedbacks);
router.post('/users', authMiddleware, addUser);
router.post('/change-password', authMiddleware, changeAdminPassword);
router.post('/create-admin', createAdmin);


export default router;