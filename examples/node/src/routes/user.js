import express from 'express';
const router = express.Router();
import user from '../controllers/userController.js';
import authMiddleware2 from '../middleware/authMiddleware2.js'
import authMiddleware from '../middleware/authMiddleware.js'

//ROTAS QUE NECESSITAM DE AUTENTICACAO
router.get('/profile', authMiddleware2, user.getProfile);
router.get('/allUsers',authMiddleware2, user.getUsers )
router.post('/updateUser', authMiddleware2, user.updateUser);

//ROTAS QUE NAO PRECISAM DE AUTENTICACAO
router.post('/login', user.singin);
router.post('/newPassword', user.singin);
router.post('/refresh', user.refreshToken);


export default router;