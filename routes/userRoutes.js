import express from 'express'
const router = express.Router();
import checkUserAuth from '../middlewares/auth-midddleware.js';

import UserController from '../controllers/userController.js'; 

// Public Routes 
router.post('/register' , UserController.userRegistration);
router.post('/login',UserController.userLogin);
router.post('/send-reset-password-email',UserController.sendUserPasswordResetEmail);
router.post('/reset/:id/:token',UserController.userPasswordReset);
// Protected Routes
router.use('/changepassword',checkUserAuth)
router.post('/changepassword',UserController.changeUserPassword);
router.use('/loggeduser',checkUserAuth);
router.get('/loggeduser',UserController.loggedUser);



export default router;